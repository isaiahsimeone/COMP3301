#include <sys/param.h>
#include <sys/systm.h>
#include <sys/fcntl.h>		/* For FWRITE */
#include <sys/ioctl.h>		/* For FIONBIO & FIONREAD */
#include <sys/kernel.h>		/* For hz and tick externs */
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/proc.h>		/* For struct process */
#include <sys/resourcevar.h>	/* For calctsru */
#include <sys/tty.h>		/* For getting controlling TTY */

#include "acct.h"

union acct_message {
	struct	acct_exit *exit;
	struct	acct_fork *fork;
	struct	acct_exec *exec;
};

struct message {
	TAILQ_ENTRY(message) entry;
	union	acct_message *acct_msg;
	int	message_type;
};
TAILQ_HEAD(, message) messages;

/* Prototypes */
unsigned int	get_sequence(void);
unsigned int	message_size(int);
void		populate_acct_common(struct process *, struct acct_common *,
		    int);
void		free_message(struct message *);
int		acctattach(dev_t, int, int, struct proc *);
int		acctopen(dev_t, int, int, struct proc *);
int		acctclose(dev_t, int, int, struct proc *);
int		acctioctl(dev_t, u_long, caddr_t, int, struct proc *);
int		acctread(dev_t, struct uio *, int);
int		acctwrite(dev_t, struct uio *, int);
int		acctkqfilter(dev_t, struct knote *);
int		acctpoll(dev_t, int, struct proc *);

/* Lock used when modifying the queue of messages */
struct rwlock msg_queue_lock = RWLOCK_INITIALIZER("messages");
/* Lock used for modifying sequence number */
struct mutex sequence_mtx;
/* Sequence number for created messages */
static unsigned int sequence_number;
/* 1 if this device is open, 0 otherwise */
static int open;
/* 1 if the device is sleeping, 0 otherwise */
static int snoozing;
/* 1 if the device is configured for non-blocking I/O, 0 otherwise */
static int fionbio = 0;

/*
 * Given a pointer to a process structre and pointer to an acct_common
 * structre, this function will populate the acct_common structure according
 * to the information contained within the process structure, for the
 * specified message type (msg_type.)
 *
 * The parameter, ac, should point to an allocated memory location
 * (via malloc.) Unspecified behaviour results when any parameter is NULL.
 *
 *	  p:   A pointer to the process structure for which the acct_common
 *	       (ac) structure should be populated for.
 *	 ac:   A pointer to the acct_common structure that should be populated
 *	       with information regarding the process (and msg_type) specified
 * msg_type:   One of ACCT_MSG_EXEC, ACCT_MSG_FORK or ACCT_MSG_EXIT.
 *
 *  returns:   void
 */
void
populate_acct_common(struct process *p, struct acct_common *ac, int msg_type)
{
	struct timespec uptime, boot, realstart, elapsed;

	/* Populate message type, length and get a new sequence number */
	ac->ac_type = msg_type;
	ac->ac_len = message_size(msg_type);
	ac->ac_seq = get_sequence();

	/* Get process name (ac_comm) */
	memcpy(ac->ac_comm, p->ps_comm, 16);

	/* As followed in native accounting (kern_acct.c) */
	nanouptime(&uptime);
	nanoboottime(&boot);
	timespecadd(&boot, &p->ps_start, &realstart);
	timespecsub(&uptime, &p->ps_start, &elapsed);
	/* Get elapsed and starting time (ac_etime, ac_btime) */
	ac->ac_etime = elapsed;
	ac->ac_btime = realstart;

	/* If this is a fork message, get parents PID. Otherwise, our own */
	ac->ac_pid = (msg_type == ACCT_MSG_FORK)
	    ? p->ps_pptr->ps_pid : p->ps_pid;

	/* Get user and group id's */
	ac->ac_uid = p->ps_ucred->cr_uid;
	ac->ac_gid = p->ps_ucred->cr_gid;

	/* If the process has a controlling tty, record it. NODEV otherwise */
	if ((p->ps_flags & PS_CONTROLT) && p->ps_pgrp->pg_session->s_ttyp)
		ac->ac_tty = p->ps_pgrp->pg_session->s_ttyp->t_dev;
	else
		ac->ac_tty = NODEV;

	/* Get process flags */
	ac->ac_flag = p->ps_acflag;
}

/*
 * Determines the size (in bytes) of a specified message type.
 * (i.e. one of ACCT_MSG_EXEC, ACCT_MSG_FORK or ACCT_MSG_EXIT.)
 *
 * msg_type:   One of ACCT_MSG_EXEC, ACCT_MSG_FORK or ACCT_MSG_EXIT.
 *
 *  returns:   The size of the specified message type (in bytes.)
 *	       (Or -1 if the specified message type is invalid.)
 */
unsigned int
message_size(int msg_type)
{
	switch (msg_type) {
	case ACCT_MSG_EXEC:
		return sizeof(struct acct_exec);
	case ACCT_MSG_EXIT:
		return sizeof(struct acct_exit);
	case ACCT_MSG_FORK:
		return sizeof(struct acct_fork);
	}
	return (-1); /* Should not be reached */
}

/*
 * Calculates and returns a sequence number which is the
 * result of the most recent call to this function, bit shifted
 * left by 0x01. Or, if the sequence number is set to 0, 0x01
 * is returned.
 *
 * Subsequent calls to this function generate the sequence:
 * 1, 2, 4, 8, 16 ... , 2^n. Upon overflow, this function will
 * wrap back around and start again from 1.
 *
 * NOTE: The sequence numbers generated depend on the 'sequence_number'
 * global, which is modified elsewhere in this file
 *
 * returns:   The previous sequence number left shifted by 0x01.
 *	      Or, 0x01 if the previous sequence number was 0.
 */
unsigned int
get_sequence()
{
	mtx_enter(&sequence_mtx);
	/*
	 * Commence the sequence starting from 0x01 if sequence number
	 * is 0, the start value, or 2^32, the overflow value.
	 */
	if (sequence_number == 0 || sequence_number == 0x80000000)
		sequence_number = 0x01;
	else
		sequence_number <<= 0x01;

	mtx_leave(&sequence_mtx);

	return sequence_number;
}

/*
 * Given a message structure, this function shall return the memory
 * used to hold said message back to the system.
 *
 *     msg:   The message structure that should be free'd.
 *
 * returns:   void
 */
void
free_message(struct message *msg)
{
	switch (msg->message_type) {
	case ACCT_MSG_EXEC:
		free(msg->acct_msg->exec, M_TEMP, message_size(ACCT_MSG_EXEC));
		break;
	case ACCT_MSG_EXIT:
		free(msg->acct_msg->exit, M_TEMP, message_size(ACCT_MSG_EXIT));
		break;
	case ACCT_MSG_FORK:
		free(msg->acct_msg->fork, M_TEMP, message_size(ACCT_MSG_FORK));
		break;
	}
	free(msg->acct_msg, M_TEMP, sizeof(union acct_message));
	free(msg, M_TEMP, sizeof(struct message));
}

/*
 * Called by the kernel upon a process forking. This function creates
 * and queues (into the messages TAILQ) a message (struct message)
 * containing the information of a process that just forked on the system.
 *
 * process:   The process that forked and lead to this function call.
 *
 * returns:   void
 */
void
acct_fork(struct process *p)
{
	struct message *msg;
	struct acct_fork *fork;
	union acct_message *acct_msg;

	/* No recording if the device isn't open */
	if (open == 0)
		return ;
	if (snoozing == 1)
		wakeup(&messages);
	fork = malloc(sizeof(struct acct_fork), M_TEMP, M_WAITOK);
	/* Populate the acct_common struct in the message */
	populate_acct_common(p, &fork->ac_common, ACCT_MSG_FORK);

	/* Populate fork->ac_cpid ac_cpid) */
	fork->ac_cpid = p->ps_pid;

	/* Create the message structure for queuing */
	msg = malloc(sizeof(struct message), M_TEMP, M_WAITOK);
	acct_msg = malloc(sizeof(union acct_message), M_TEMP, M_WAITOK);
	acct_msg->fork = fork;
	msg->acct_msg = acct_msg;
	msg->message_type = ACCT_MSG_FORK;
	/* Safely queue the message */
	rw_enter_write(&msg_queue_lock);
	TAILQ_INSERT_TAIL(&messages, msg, entry);
	rw_exit_write(&msg_queue_lock);
}

/*
 * Called by the kernel upon a process executing. This function creates
 * and queues (into the messages TAILQ) a message (struct message)
 * containing the information of a process that was just executed on the
 * system.
 *
 * process:   The process that was executed and lead to this function call.
 *
 * returns:   void
 */
void
acct_exec(struct process *p)
{
	struct message *msg;
	struct acct_exec *exec;
	union acct_message *acct_msg;

	/* No recording if the device isn't open */
	if (open == 0)
		return ;
	if (snoozing == 1)
		wakeup(&messages);

	exec = malloc(sizeof(struct acct_exec), M_TEMP, M_WAITOK);
	/* Populate the acct_common struct in the message */
	populate_acct_common(p, &exec->ac_common, ACCT_MSG_EXEC);

	/* Create the message structure for queuing */
	msg = malloc(sizeof(struct message), M_TEMP, M_WAITOK);
	acct_msg = malloc(sizeof(union acct_message), M_TEMP, M_WAITOK);
	acct_msg->exec = exec;
	msg->acct_msg = acct_msg;
	msg->message_type = ACCT_MSG_EXEC;
	/* Safely queue the message */
	rw_enter_write(&msg_queue_lock);
	TAILQ_INSERT_TAIL(&messages, msg, entry);
	rw_exit_write(&msg_queue_lock);
}

/*
 * Called by the kernel upon a process exiting. This function creates
 * and queues (into the messages TAILQ) a message (struct message)
 * containing the information of a process that just exited on the system.
 *
 * process:   The process that exited and lead to this function call.
 *
 * returns:   void
 */
void
acct_exit(struct process *p)
{
	struct timespec ut, st, sum;
	struct message *msg;
	struct acct_exit *exit;
	union acct_message *acct_msg;
	struct proc *proc;
	int time;

	/* No recording if the device isn't open */
	if (open == 0)
		return ;
	/* Wake if sleeping */
	if (snoozing == 1)
		wakeup(&messages);

	exit = malloc(sizeof(struct acct_exit), M_TEMP, M_WAITOK);
	/* Populate the acct_common struct in the message */
	populate_acct_common(p, &exit->ac_common, ACCT_MSG_EXIT);

	/* User and sys time (ac_utime & ac_stime respectively) */
	calctsru(&p->ps_tu, &ut, &st, NULL);
	exit->ac_utime = ut;
	exit->ac_stime = st;

	/* Average memory usage (ac_mem) */
	proc = p->ps_mainproc;
	timespecadd(&ut, &st, &sum);
	time = sum.tv_sec * hz + sum.tv_nsec / (1000 * tick);
	if (time)
		exit->ac_mem = (uint64_t)(proc->p_ru.ru_ixrss +
		    proc->p_ru.ru_idrss + proc->p_ru.ru_isrss) / time;
	else
		exit->ac_mem = 0;

	/* IO operations (ac_io) */
	exit->ac_io = proc->p_ru.ru_inblock + proc->p_ru.ru_oublock;

	/* Create the message structure for queuing */
	msg = malloc(sizeof(struct message), M_TEMP, M_WAITOK);
	acct_msg = malloc(sizeof(union acct_message), M_TEMP, M_WAITOK);
	acct_msg->exit = exit;
	msg->acct_msg = acct_msg;
	msg->message_type = ACCT_MSG_EXIT;
	/* Safely queue the message */
	rw_enter_write(&msg_queue_lock);
	TAILQ_INSERT_TAIL(&messages, msg, entry);
	rw_exit_write(&msg_queue_lock);
}

/*
 * Called by the kernel upon it becoming ready to attach the driver.
 *
 * NOTE: This function modifies the global variable sequence_number.
 *	 And initialises the message queue.
 *
 * returns:   0
 */
int
acctattach(dev_t dev, int flag, int mode, struct proc *p)
{
	TAILQ_INIT(&messages);
	sequence_number = 0;

	return (0);
}

/*
 * Called indirectly by a userland open the device.
 *
 * The device may be open only for reading. Opened with minor 0,
 * and opened exclusively.
 *
 * NOTE: This function modifies the global variable 'sequence_number'
 *
 * returns:   EPERM if an attempt was made to open the device
 *	      in writing mode.
 *	      ENXIO if the minor number of the specified device
 *	      is not 0.
 *	      EBUSY if the device is already open somewhere.
 *	      0 upon success.
 */
int
acctopen(dev_t dev, int flag, int mode, struct proc *p)
{
	if (open == 1)
		return (EBUSY);
	if (minor(dev) != 0)
		return (ENXIO);
	if ((flag & FWRITE))
		return (EPERM);

	/* Device considered open upon reaching this line */
	sequence_number = 0;
	open = 1;

	mtx_init(&sequence_mtx, IPL_NONE);

	return (0);
}

/*
 * Called indirectly by a userland upon closure of the device file
 * (i.e. terminating a read)
 *
 * NOTES: Global variable sequence_number is reset by this function.
 *	  The queue of messages is released regardless of whether
 *	  they've been read or not.
 *
 * returns:   0
 */
int
acctclose(dev_t dev, int flag, int mode, struct proc *p)
{
	struct message *m, *tm;

	/* Device now considered to be closed */
	sequence_number = 0;
	open = 0;
	fionbio = 0;

	/* Remove and Free all messages safely */
	rw_enter_write(&msg_queue_lock);
	TAILQ_FOREACH_SAFE(m, &messages, entry, tm) {
		TAILQ_REMOVE(&messages, m, entry);
		free_message(m);
	}
	rw_exit_write(&msg_queue_lock);

	return (0);
}

/*
 * Called indirectly by a userland process attempting to configure
 * the device via the ioctl call.
 *
 * NOTE: Only FIONBIO and FIONREAD are supported by this device.
 *
 * returns:   0 upon success
 *	      ENOTTY if an unsupported request is made (cmd)
 */
int
acctioctl(dev_t dev, u_long cmd, caddr_t data, int fflag, struct proc *p)
{
	struct message *m;
	int sz_ready = 0;

	switch (cmd) {
	case FIONBIO:
		/* Enable non-blocking I/O */
		fionbio = 1;
		break;
	case FIONREAD:
		/* Calculate how many bytes are ready to read */
		rw_enter_read(&msg_queue_lock);
		/* Is there any entry in the queue? */
		if (!TAILQ_EMPTY(&messages)) {
			/* Get size of first entry (not sum of all) */
			m = TAILQ_FIRST(&messages);
			sz_ready = message_size(m->message_type);
		}
		*(int *)data = sz_ready;
		rw_exit_read(&msg_queue_lock);
		break;
	default:
		return (ENOTTY); /* Not implemented */
	}

	return (0);
}

/*
 * Called indirectly by a userland process attempting to read from
 * the device. Reading from the device is blocking, unless it is
 * configured with the FIONBIO flag (ioctl.)
 *
 * With blocking enabled, the driver will sleep until a message
 * becomes available for reading to userland, or if it is sent
 * a signal.
 *
 * returns:   0 on success
 *	      EINVAL if uio->uio_offset < 0
 *	      or EAGAIN if the device is configured to be non-blocking,
 *	      and no message is available for reading.
 */
int
acctread(dev_t dev, struct uio *uio, int ioflag)
{
	size_t len;
	int error;
	unsigned int msg_sz;
	void *msg_ptr;

	if (uio->uio_offset < 0)
		return (EINVAL);

	/* If there are no messages, block (if fionbio == 0) */
	if (TAILQ_EMPTY(&messages)) {
		/* Non-Blocking I/O */
		if (fionbio == 1)
			return EAGAIN; /* As per ioctl(2) */

		/* Blocking I/O */
		snoozing = 1;
		/* Will be awoken upon some exec/exit/fork or signal */
		tsleep(&messages, PRIBIO | PCATCH, "awt_msg", 0);
		snoozing = 0;
	}

	/* Dequeue one single message safely */
	rw_enter_read(&msg_queue_lock);
	struct message *msg = TAILQ_FIRST(&messages);
	rw_exit_read(&msg_queue_lock);

	/* Just in case */
	if (msg == NULL)
		return (0);

	/* Calculate message size and obtain pointer to said message */
	msg_sz = message_size(msg->message_type);
	switch (msg->message_type) {
	case ACCT_MSG_EXEC:
		msg_ptr = msg->acct_msg->exec;
		break;
	case ACCT_MSG_EXIT:
		msg_ptr = msg->acct_msg->exit;
		break;
	case ACCT_MSG_FORK:
		msg_ptr = msg->acct_msg->fork;
		break;
	}

	/* Read the whole message (or the size requested to userland) */
	len = ulmin(uio->uio_resid, msg_sz);
	if ((error = uiomove(msg_ptr, len, uio) != 0))
		return (error);

	/* Remove the message from the queue safely */
	rw_enter_write(&msg_queue_lock);
	TAILQ_REMOVE(&messages, msg, entry);
	free_message(msg);
	rw_exit_write(&msg_queue_lock);

	return (0);
}

/*
 * OPERATION NOT SUPPORTED
 *
 * returns:   EOPNOTSUPP
 */
int
acctwrite(dev_t dev, struct uio *uio, int ioflag)
{
	return (EOPNOTSUPP);
}

/*
 * OPERATION NOT SUPPORTED
 *
 * returns:   EOPNOTSUPP
 */
int
acctkqfilter(dev_t dev, struct knote *kn)
{
	return (EOPNOTSUPP);
}

/*
 * OPERATION NOT SUPPORTED
 *
 * returns:   EOPNOTSUPP
 */
int
acctpoll(dev_t dev, int events, struct proc *p)
{
	return (EOPNOTSUPP);
}