/*
 * Copyright (c) 2009 Mark Heily <mark@heily.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "private.h"

#ifndef NDEBUG
static char *
inotify_mask_dump(uint32_t mask)
{
    static __thread char buf[1024];

#define INEVT_MASK_DUMP(attrib) \
    if (mask & attrib) \
       strcat(buf, #attrib" ");

    snprintf(buf, sizeof(buf), "mask = %d (", mask);
    INEVT_MASK_DUMP(IN_ACCESS);
    INEVT_MASK_DUMP(IN_MODIFY);
    INEVT_MASK_DUMP(IN_ATTRIB);
    INEVT_MASK_DUMP(IN_CLOSE_WRITE);
    INEVT_MASK_DUMP(IN_CLOSE_NOWRITE);
    INEVT_MASK_DUMP(IN_OPEN);
    INEVT_MASK_DUMP(IN_MOVED_FROM);
    INEVT_MASK_DUMP(IN_MOVED_TO);
    INEVT_MASK_DUMP(IN_CREATE);
    INEVT_MASK_DUMP(IN_DELETE);
    INEVT_MASK_DUMP(IN_DELETE_SELF);
    INEVT_MASK_DUMP(IN_MOVE_SELF);
    buf[strlen(buf) - 1] = ')';

    return (buf);
}

static char *
inotify_event_dump(struct inotify_event *evt)
{
    static __thread char buf[1024];

    snprintf(buf, sizeof(buf), "wd=%d mask=%s", 
            evt->wd,
            inotify_mask_dump(evt->mask));

    return (buf);
}

#endif /* !NDEBUG */


/* TODO: USE this to get events with name field */
int
get_one_event(struct inotify_event *dst, int inofd)
{
    ssize_t n;

    dbg_puts("reading one inotify event");
    for (;;) {
        n = read(inofd, dst, sizeof(*dst) + 255 + 1);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            dbg_perror("read");
            return (-1);
        } else {
            break;
        }
    }
    dbg_printf("read(2) from inotify wd: %ld bytes", (long) n);

    return (0);
}

static int
add_watch(struct filter *filt, struct knote *kn)
{
    struct epoll_event ev;
    int ifd;
    char path[PATH_MAX];
    uint32_t mask;

    /* Convert the fd to a pathname */
    if (linux_fd_to_path(&path[0], sizeof(path), kn->kev.ident) < 0)
        return (-1);

    /* Convert the fflags to the inotify mask */
#ifdef DARLING
    /*
     * x86Code: not IN_CLOSE. The watch is on the file (inode), so IN_CLOSE fired whenever any process closed it
     * (cfprefsd reading a plist), and copyout then deleted the knote. Darling's close() hook (kqueue_closed_fd)
     * already drops the knotes of a descriptor this process closes, as XNU does.
     */
    mask = 0;
#else
    mask = IN_CLOSE;
#endif
    if (kn->kev.fflags & NOTE_DELETE)
        mask |= IN_ATTRIB | IN_DELETE_SELF;
    if (kn->kev.fflags & NOTE_WRITE)      
        mask |= IN_MODIFY | IN_ATTRIB;
    if (kn->kev.fflags & NOTE_EXTEND)
        mask |= IN_MODIFY | IN_ATTRIB;
    if ((kn->kev.fflags & NOTE_ATTRIB) || 
            (kn->kev.fflags & NOTE_LINK))
        mask |= IN_ATTRIB;
    if (kn->kev.fflags & NOTE_RENAME)
        mask |= IN_MOVE_SELF;
#ifdef DARLING
    if (mask == 0) /* x86Code: inotify needs some event; copyout drops events that map to no requested fflags */
        mask = IN_DELETE_SELF;
#endif
    if (kn->kev.flags & EV_ONESHOT)
        mask |= IN_ONESHOT;

    /* Create an inotify descriptor */
    ifd = inotify_init();
    if (ifd < 0) {
        dbg_perror("inotify_init(2)");
        return (-1);
    }
#ifdef DARLING
    /* x86Code: non-blocking, so a copyout with nothing left to read can't hang the kevent caller */
    (void) fcntl(ifd, F_SETFL, O_NONBLOCK);
#endif

    /* Add the watch */
    dbg_printf("inotify_add_watch(2); inofd=%d, %s, path=%s", 
            ifd, inotify_mask_dump(mask), path);
#ifdef DARLING
    /*
     * x86Code: the path read from /proc/<pid>/fd/<n> is a Linux path, and Darling's inotify_add_watch() expands every
     * path into the prefix: a file outside it (/home/... -> <prefix>/home/...) was never found, the kevent failed
     * and libdispatch crashed the process (fileproviderd: the simulator's memory-pressure source is a vnode watch on
     * $SIMULATOR_MEMORY_WARNINGS). Watch the open file itself, through Linux's /proc/self/fd/<n> magic link.
     */
    {
        char fdpath[64];
        long r;
        snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", (int) kn->kev.ident);
        r = __linux_syscall(254 /* __NR_inotify_add_watch, x86-64 */, ifd, (long) fdpath, mask);
        if (r < 0) {
            errno = (r == -2) ? ENOENT : (r == -13) ? EACCES : (r == -28) ? ENOSPC : EINVAL;
            kn->kev.data = -1;
        } else
            kn->kev.data = r;
    }
#else
    kn->kev.data = inotify_add_watch(ifd, path, mask);
#endif
    if (kn->kev.data < 0) {
        dbg_perror("inotify_add_watch(2)");
        goto errout;
    }

    /* Add the inotify fd to the epoll set */
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.ptr = kn;
    if (epoll_ctl(filter_epfd(filt), EPOLL_CTL_ADD, ifd, &ev) < 0) {
        dbg_perror("epoll_ctl(2)");
        goto errout;
    }

    kn->kdata.kn_inotifyfd = ifd;

    return (0);

errout:
    kn->kdata.kn_inotifyfd = -1;
    (void) __close_for_kqueue(ifd);
    return (-1);
}

static int
delete_watch(struct filter *filt, struct knote *kn)
{
    int ifd = kn->kdata.kn_inotifyfd;

    if (ifd < 0)
        return (0);
    if (epoll_ctl(filter_epfd(filt), EPOLL_CTL_DEL, ifd, NULL) < 0) {
        dbg_perror("epoll_ctl(2)");
        return (-1);
    }
    (void) __close_for_kqueue(ifd);
    kn->kdata.kn_inotifyfd = -1;

    return (0);
}

int
evfilt_vnode_copyout(struct kevent64_s *dst, struct knote *src, void *ptr UNUSED)
{
    struct inotify_event* evt = (struct inotify_event*) __builtin_alloca(sizeof(struct inotify_event) + 255 + 1);
    struct stat sb;

    if (get_one_event(evt, src->kdata.kn_inotifyfd) < 0) {
#ifdef DARLING
        /* x86Code: nothing to read (another thread took it; the descriptor is non-blocking): not an error, which
           would abort() in linux_kevent_copyout */
        dst->filter = EVFILT_DROP;
        return (0);
#else
        return (-1);
#endif
    }

    dbg_printf("inotify event: %s", inotify_event_dump(evt));
    if (evt->mask & IN_IGNORED) {
        /* TODO: possibly return error when fs is unmounted */
        dst->filter = EVFILT_DROP;
        return (0);
    }

    /* Check if the watched file has been closed, and 
       XXX-this may not exactly match the kevent() behavior if multiple file de
scriptors reference the same file.
    */
    if (evt->mask & IN_CLOSE_WRITE || evt->mask & IN_CLOSE_NOWRITE) {
        src->kn_flags |= EV_ONESHOT; /* KLUDGE: causes the knote to be deleted */
        dst->filter = EVFILT_DROP_POSTPROCESS; /* KLUDGE: causes the event to be discarded */
        return (0);
    }

    kevent_int_to_64(&src->kev, dst);
    dst->data = 0;
#ifdef DARLING
    dst->fflags = 0; /* x86Code: report what happened, not every requested flag (filled in below) */
#endif

    /* No error checking because fstat(2) should rarely fail */
    //FIXME: EINTR
    if ((evt->mask & IN_ATTRIB || evt->mask & IN_MODIFY) 
        && fstat(src->kev.ident, &sb) == 0) {
        if (sb.st_nlink == 0 && src->kev.fflags & NOTE_DELETE) 
            dst->fflags |= NOTE_DELETE;
        if (sb.st_nlink != src->data.vnode.nlink && src->kev.fflags & NOTE_LINK) 
            dst->fflags |= NOTE_LINK;
#if HAVE_NOTE_TRUNCATE
        if (sb.st_nsize == 0 && src->kev.fflags & NOTE_TRUNCATE) 
            dst->fflags |= NOTE_TRUNCATE;
#endif
        if (sb.st_size > src->data.vnode.size && src->kev.fflags & NOTE_WRITE) 
            dst->fflags |= NOTE_EXTEND;
       src->data.vnode.nlink = sb.st_nlink;
       src->data.vnode.size = sb.st_size;
    }

    if (evt->mask & IN_MODIFY && src->kev.fflags & NOTE_WRITE) 
        dst->fflags |= NOTE_WRITE;
    if (evt->mask & IN_ATTRIB && src->kev.fflags & NOTE_ATTRIB) 
        dst->fflags |= NOTE_ATTRIB;
    if (evt->mask & IN_MOVE_SELF && src->kev.fflags & NOTE_RENAME) 
        dst->fflags |= NOTE_RENAME;
    if (evt->mask & IN_DELETE_SELF && src->kev.fflags & NOTE_DELETE) 
        dst->fflags |= NOTE_DELETE;

    if (evt->mask & IN_MODIFY && src->kev.fflags & NOTE_WRITE) 
        dst->fflags |= NOTE_WRITE;
    if (evt->mask & IN_ATTRIB && src->kev.fflags & NOTE_ATTRIB) 
        dst->fflags |= NOTE_ATTRIB;
    if (evt->mask & IN_MOVE_SELF && src->kev.fflags & NOTE_RENAME) 
        dst->fflags |= NOTE_RENAME;
    if (evt->mask & IN_DELETE_SELF && src->kev.fflags & NOTE_DELETE) 
        dst->fflags |= NOTE_DELETE;

#ifdef DARLING
    /* x86Code: an event none of the requested fflags cover (XNU wouldn't fire) */
    if (dst->fflags == 0)
        dst->filter = EVFILT_DROP;
#endif
    return (0);
}

int
evfilt_vnode_knote_create(struct filter *filt, struct knote *kn)
{
    struct stat sb;

    if (fstat(kn->kev.ident, &sb) < 0) {
        dbg_puts("fstat failed");
        return (-1);
    }
    kn->data.vnode.nlink = sb.st_nlink;
    kn->data.vnode.size = sb.st_size;
    kn->kev.data = -1;
#ifdef DARLING
    kn->kdata.kn_inotifyfd = -1; /* x86Code: no watch yet (see evfilt_vnode_knote_enable) */
#endif

    return (add_watch(filt, kn));
}

int
evfilt_vnode_knote_modify(struct filter *filt, struct knote *kn, 
        const struct kevent64_s *kev)
{
#ifdef DARLING
    /*
     * x86Code: EV_ADD on an existing vnode knote takes the new fflags (XNU's filt_vntouch). It was a stub that
     * failed, so libdispatch saw the update as an error (LIBDISPATCH_STRICT processes such as fileproviderd crash on
     * any kevent error).
     */
    if (kev->fflags == kn->kev.fflags && kn->kdata.kn_inotifyfd >= 0)
        return (0);
    kn->kev.fflags = kev->fflags;
    if (kn->kev.flags & EV_DISABLE)
        return (0);
    if (delete_watch(filt, kn) < 0)
        return (-1);
    return (add_watch(filt, kn));
#else
    (void)filt;
    (void)kn;
    (void)kev;
    return (-1); /* FIXME - STUB */
#endif
}

int
evfilt_vnode_knote_delete(struct filter *filt, struct knote *kn)
{   
    return delete_watch(filt, kn);
}

int
evfilt_vnode_knote_enable(struct filter *filt, struct knote *kn)
{
#ifdef DARLING
    /*
     * x86Code: EV_ENABLE on a knote that is already watching. add_watch() made a second inotify instance and lost
     * the first (still open, still in the epoll set): every re-enable leaked one, until inotify_init() failed with
     * EMFILE (the per-user instance limit) and the next vnode EV_ADD in any simulator process failed
     * (fileproviderd: "vnode add" EMFILE, crashed by LIBDISPATCH_STRICT).
     */
    if (kn->kdata.kn_inotifyfd >= 0)
        return (0);
#endif
    return add_watch(filt, kn);
}

int
evfilt_vnode_knote_disable(struct filter *filt, struct knote *kn)
{
    return delete_watch(filt, kn);
}

const struct filter evfilt_vnode = {
    EVFILT_VNODE,
    NULL,
    NULL,
    evfilt_vnode_copyout,
    evfilt_vnode_knote_create,
    evfilt_vnode_knote_modify,
    evfilt_vnode_knote_delete,
    evfilt_vnode_knote_enable,
    evfilt_vnode_knote_disable,        
};
