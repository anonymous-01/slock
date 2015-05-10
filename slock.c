
/* See LICENSE file for license details. */
#define _XOPEN_SOURCE 500
#if HAVE_SHADOW_H
#include <shadow.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <X11/keysym.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/XKBlib.h>

#if HAVE_BSD_AUTH
#include <login_cap.h>
#include <bsd_auth.h>
#endif

#include "config.h"

typedef struct {
    int screen;
    Window root, win;
    Pixmap pmap;
    unsigned long colors[3];
    XGCValues gr_values;
} Lock;

typedef struct {
    int device_id;
    XkbDescRec *desc;
    char layout[16];
} Keyboard;

static Lock **locks;
static int nscreens;
static Bool running = True;

static void
die(const char *errstr, ...) {
    va_list ap;

    va_start(ap, errstr);
    vfprintf(stderr, errstr, ap);
    va_end(ap);
    exit(EXIT_FAILURE);
}

static bool
kb_goodsym(char *sym) {
    static char *nonsyms[9] = {
        "group",
        "inet",
        "ctr",
        "pc",
        "ctrl",
        "capslock",
        "compose",
        "terminate",
        "eurosign",
    };

    for (int i = 0; i < 9; i++)
        if (strcmp(sym, nonsyms[i]) == 0)
            return false;

    return true;
}

static bool
kb_goodchar(char ch) {
    return isdigit(ch) || isalpha(ch) || ch == '_' || ch == '-';
}

static int
kb_parse_atom(const char *symbols, const int index, char *result) {
    enum {ok, skip, broken} state = ok;
    int paren = 0;

    char sym[16];
    int symlen = 0;

    int found_index = 0;

    for (int i = 0; i < strlen(symbols); i++) {
        char ch = symbols[i];

        if (ch == '+' || ch == '_') {
            if (paren == 0) {
                if (state != broken && paren == 0 && kb_goodsym(sym)) {
                    if (found_index == index) {
                        strcpy(result, sym);
                        return 0;
                    }
                    found_index++;
                }

                state = ok;
                
                sym[0] = '\0';
                symlen = 0;
            }
        } else if (state == ok && ch == '(') {
            paren++;
        } else if (state == ok && ch == ')') {
            paren--;
        } else if (state == ok && ch == ':') {
            state = skip;
        } else if (state == ok && kb_goodchar(ch)) {
            if (paren == 0 && symlen < 15) {
                sym[symlen++] = ch;
                sym[symlen] = '\0';
            }
        } else if (state == ok) {
            state = broken;
        }
    }

    if (state != broken && paren == 0 && kb_goodsym(sym)) {
        if (found_index == index) {
            strcpy(result, sym);
            return 0;
        }
    }

    return 1;
}

static void
kb_load_layout(Display *dpy, Keyboard *kb) {
    /* Read atom name */
    XkbGetControls(dpy, XkbAllControlsMask, kb->desc);
    XkbGetNames(dpy, XkbSymbolsNameMask, kb->desc);

    Atom symNameAtom = kb->desc->names->symbols;
    char *kbsC = XGetAtomName(dpy, symNameAtom);

    /* Read current group */
    XkbStateRec xkbState;
    XkbGetState(dpy, kb->device_id, &xkbState);

    /* Get layout as a string */
    kb_parse_atom(kbsC, (int)xkbState.group, kb->layout);

    XFree(kbsC);
}

#ifdef __linux__
#include <fcntl.h>

static void
dontkillme(void) {
    int fd;

    fd = open("/proc/self/oom_score_adj", O_WRONLY);
    if (fd < 0 && errno == ENOENT)
        return;
    if (fd < 0 || write(fd, "-1000\n", 6) != 6 || close(fd) != 0)
        die("cannot disable the out-of-memory killer for this process\n");
}
#endif

#ifndef HAVE_BSD_AUTH
static const char *
getpw(void) { /* only run as root */
    const char *rval;
    struct passwd *pw;

    errno = 0;
    pw = getpwuid(getuid());
    if (!pw) {
        if (errno)
            die("slock: getpwuid: %s\n", strerror(errno));
        else
            die("slock: cannot retrieve password entry (make sure to suid or sgid slock)\n");
    }
    rval =  pw->pw_passwd;

#if HAVE_SHADOW_H
    if (rval[0] == 'x' && rval[1] == '\0') {
        struct spwd *sp;
        sp = getspnam(getenv("USER"));
        if(!sp)
            die("slock: cannot retrieve shadow entry (make sure to suid or sgid slock)\n");
        rval = sp->sp_pwdp;
    }
#endif

    /* drop privileges */
    if (geteuid() == 0
       && ((getegid() != pw->pw_gid && setgid(pw->pw_gid) < 0) || setuid(pw->pw_uid) < 0))
        die("slock: cannot drop privileges\n");
    return rval;
}
#endif

static void
#ifdef HAVE_BSD_AUTH
readpw(Display *dpy, Keyboard *kb)
#else
readpw(Display *dpy, Keyboard *kb, const char *pws)
#endif
{
    char buf[32], passwd[256];
    int num, screen;
    unsigned int len, llen;
    KeySym ksym;
    XEvent ev;

    len = llen = 0;
    running = True;

    /* As "slock" stands for "Simple X display locker", the DPMS settings
     * had been removed and you can set it with "xset" or some other
     * utility. This way the user can easily set a customized DPMS
     * timeout. */
    while(running && !XNextEvent(dpy, &ev)) {
        kb_load_layout(dpy, kb);
        for(screen = 0; screen < nscreens; screen++) {
            XDrawString(dpy, locks[screen]->win, XCreateGC(dpy, locks[screen]->win, GCForeground, &locks[screen]->gr_values), 30, 30, kb->layout, strlen(kb->layout));
        }

        if(ev.type == KeyPress) {
            buf[0] = 0;
            num = XLookupString(&ev.xkey, buf, sizeof buf, &ksym, 0);
            if(IsKeypadKey(ksym)) {
                if(ksym == XK_KP_Enter)
                    ksym = XK_Return;
                else if(ksym >= XK_KP_0 && ksym <= XK_KP_9)
                    ksym = (ksym - XK_KP_0) + XK_0;
            }
            if(IsFunctionKey(ksym) || IsKeypadKey(ksym)
                    || IsMiscFunctionKey(ksym) || IsPFKey(ksym)
                    || IsPrivateKeypadKey(ksym))
                continue;
            switch(ksym) {
            case XK_Return:
                passwd[len] = 0;
#ifdef HAVE_BSD_AUTH
                running = !auth_userokay(getlogin(), NULL, "auth-xlock", passwd);
#else
                running = !!strcmp(crypt(passwd, pws), pws);
#endif
                if(running)
                    XBell(dpy, 100);
                len = 0;
                break;
            case XK_Escape:
                len = 0;
                break;
            case XK_BackSpace:
                if(len)
                    --len;
                break;
            default:
                if(num && !iscntrl((int) buf[0]) && (len + num < sizeof passwd)) {
                    memcpy(passwd + len, buf, num);
                    len += num;
                }
                break;
            }
            if(llen == 0 && len != 0) {
                for(screen = 0; screen < nscreens; screen++) {
                    XSetWindowBackground(dpy, locks[screen]->win, locks[screen]->colors[1]);
                }
            } else if(llen != 0 && len == 0) {
                for(screen = 0; screen < nscreens; screen++) {
                    XSetWindowBackground(dpy, locks[screen]->win, locks[screen]->colors[0]);
                }
            }
            llen = len;
        } else {
            for(screen = 0; screen < nscreens; screen++) {
                XRaiseWindow(dpy, locks[screen]->win);
            }
        }
        
        kb_load_layout(dpy, kb);
        for(screen = 0; screen < nscreens; screen++) {
            XClearWindow(dpy, locks[screen]->win);
            XDrawString(dpy, locks[screen]->win, XCreateGC(dpy, locks[screen]->win, GCForeground, &locks[screen]->gr_values), 30, 30, kb->layout, strlen(kb->layout));
        }
    }
}

static void
unlockscreen(Display *dpy, Lock *lock) {
    if(dpy == NULL || lock == NULL)
        return;

    XUngrabPointer(dpy, CurrentTime);
    XFreeColors(dpy, DefaultColormap(dpy, lock->screen), lock->colors, 2, 0);
    XFreePixmap(dpy, lock->pmap);
    XDestroyWindow(dpy, lock->win);

    free(lock);
}

static Lock *
lockscreen(Display *dpy, int screen) {
    char curs[] = {0, 0, 0, 0, 0, 0, 0, 0};
    unsigned int len;
    Lock *lock;
    XColor color, dummy;
    XSetWindowAttributes wa;
    Cursor invisible;

    if(dpy == NULL || screen < 0)
        return NULL;

    lock = malloc(sizeof(Lock));
    if(lock == NULL)
        return NULL;

    lock->screen = screen;

    lock->root = RootWindow(dpy, lock->screen);

    /* init */
    wa.override_redirect = 1;
    wa.background_pixel = BlackPixel(dpy, lock->screen);
    lock->win = XCreateWindow(dpy, lock->root, 0, 0, DisplayWidth(dpy, lock->screen), DisplayHeight(dpy, lock->screen),
            0, DefaultDepth(dpy, lock->screen), CopyFromParent,
            DefaultVisual(dpy, lock->screen), CWOverrideRedirect | CWBackPixel, &wa);

    XAllocNamedColor(dpy, DefaultColormap(dpy, lock->screen), COLOR2, &color, &dummy);
    lock->colors[1] = color.pixel;

    XAllocNamedColor(dpy, DefaultColormap(dpy, lock->screen), COLOR1, &color, &dummy);
    lock->colors[0] = color.pixel;

    XAllocNamedColor(dpy, DefaultColormap(dpy, lock->screen), COLOR3, &color, &dummy);
    lock->colors[2] = color.pixel;

    lock->pmap = XCreateBitmapFromData(dpy, lock->win, curs, 8, 8);
    lock->gr_values.foreground = lock->colors[2];

    invisible = XCreatePixmapCursor(dpy, lock->pmap, lock->pmap, &color, &color, 0, 0);
    XDefineCursor(dpy, lock->win, invisible);
    XMapRaised(dpy, lock->win);
    for(len = 1000; len; len--) {
        if(XGrabPointer(dpy, lock->root, False, ButtonPressMask | ButtonReleaseMask | PointerMotionMask,
            GrabModeAsync, GrabModeAsync, None, invisible, CurrentTime) == GrabSuccess)
            break;
        usleep(1000);
    }
    if(running && (len > 0)) {
        for(len = 1000; len; len--) {
            if(XGrabKeyboard(dpy, lock->root, True, GrabModeAsync, GrabModeAsync, CurrentTime)
                == GrabSuccess)
                break;
            usleep(1000);
        }
    }

    running &= (len > 0);
    if(!running) {
        unlockscreen(dpy, lock);
        lock = NULL;
    }
    else 
        XSelectInput(dpy, lock->root, SubstructureNotifyMask);

    return lock;
}

static void
usage(void) {
    fprintf(stderr, "usage: slock [-v]\n");
    exit(EXIT_FAILURE);
}

int
main(int argc, char **argv) {
#ifndef HAVE_BSD_AUTH
    const char *pws;
#endif
    Display *dpy;
    int screen;

    Keyboard kb;
    kb.device_id = XkbUseCoreKbd;
    strcpy(kb.layout, "unknown");

    XkbIgnoreExtension(False);

    if((argc == 2) && !strcmp("-v", argv[1]))
        die("slock-%s, © 2006-2014 slock engineers\n", VERSION);
    else if(argc != 1)
        usage();

#ifdef __linux__
    dontkillme();
#endif

    if(!getpwuid(getuid()))
        die("slock: no passwd entry for you\n");

#ifndef HAVE_BSD_AUTH
    pws = getpw();
#endif

    if(!(dpy = XOpenDisplay(0)))
        die("slock: cannot open display\n");

    /* Get the number of screens in display "dpy" and blank them all. */
    nscreens = ScreenCount(dpy);
    locks = malloc(sizeof(Lock *) * nscreens);
    if(locks == NULL)
        die("slock: malloc: %s\n", strerror(errno));
    int nlocks = 0;
    for(screen = 0; screen < nscreens; screen++) {
        if ( (locks[screen] = lockscreen(dpy, screen)) != NULL)
            nlocks++;
    }
    XSync(dpy, False);

    /* Did we actually manage to lock something? */
    if (nlocks == 0) { // nothing to protect
        free(locks);
        XCloseDisplay(dpy);
        return 1;
    }

    kb.desc = XkbAllocKeyboard();
    if (kb.desc == NULL) {
        free(locks);
        XCloseDisplay(dpy);
        die("slock: cannot alloc keyboard");
        return 1;
    }

    kb.desc->dpy = dpy;

    /* Everything is now blank. Now wait for the correct password. */
#ifdef HAVE_BSD_AUTH
    readpw(dpy, &kb);
#else
    readpw(dpy, &kb, pws);
#endif

    /* Password ok, unlock everything and quit. */
    for(screen = 0; screen < nscreens; screen++)
        unlockscreen(dpy, locks[screen]);

    free(locks);
    XCloseDisplay(dpy);
    XkbFreeKeyboard(kb.desc, 0, true);

    return 0;
}
