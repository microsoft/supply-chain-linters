// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"cmp"
	"debug/elf"
	"errors"
	"fmt"
	"log"
	"maps"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/arch/x86/x86asm"
)

const syscalls = `0	read	read(2)	sys_read
1	write	write(2)	sys_write
2	open	open(2)	sys_open
3	close	close(2)	sys_close
4	stat	stat(2)	sys_newstat
5	fstat	fstat(2)	sys_newfstat
6	lstat	lstat(2)	sys_newlstat
7	poll	poll(2)	sys_poll
8	lseek	lseek(2)	sys_lseek
9	mmap	mmap(2)	sys_ksys_mmap_pgoff
10	mprotect	mprotect(2)	sys_mprotect
11	munmap	munmap(2)	sys_munmap
12	brk	brk(2)	sys_brk
13	rt_sigaction	rt_sigaction(2)	sys_rt_sigaction
14	rt_sigprocmask	rt_sigprocmask(2)	sys_rt_sigprocmask
15	rt_sigreturn	rt_sigreturn(2)	sys_rt_sigreturn
16	ioctl	ioctl(2)	sys_ioctl
17	pread64	pread64(2)	sys_pread64
18	pwrite64	pwrite64(2)	sys_pwrite64
19	readv	readv(2)	sys_readv
20	writev	writev(2)	sys_writev
21	access	access(2)	sys_access
22	pipe	pipe(2)	sys_pipe
23	select	select(2)	sys_select
24	sched_yield	sched_yield(2)	sys_sched_yield
25	mremap	mremap(2)	sys_mremap
26	msync	msync(2)	sys_msync
27	mincore	mincore(2)	sys_mincore
28	madvise	madvise(2)	sys_madvise
29	shmget	shmget(2)	sys_shmget
30	shmat	shmat(2)	sys_shmat
31	shmctl	shmctl(2)	sys_shmctl
32	dup	dup(2)	sys_dup
33	dup2	dup2(2)	sys_dup2
34	pause	pause(2)	sys_pause
35	nanosleep	nanosleep(2)	sys_nanosleep
36	getitimer	getitimer(2)	sys_getitimer
37	alarm	alarm(2)	sys_alarm
38	setitimer	setitimer(2)	sys_setitimer
39	getpid	getpid(2)	sys_getpid
40	sendfile	sendfile(2)	sys_sendfile64
41	socket	socket(2)	sys_socket
42	connect	connect(2)	sys_connect
43	accept	accept(2)	sys_accept
44	sendto	sendto(2)	sys_sendto
45	recvfrom	recvfrom(2)	sys_recvfrom
46	sendmsg	sendmsg(2)	sys_sendmsg
47	recvmsg	recvmsg(2)	sys_recvmsg
48	shutdown	shutdown(2)	sys_shutdown
49	bind	bind(2)	sys_bind
50	listen	listen(2)	sys_listen
51	getsockname	getsockname(2)	sys_getsockname
52	getpeername	getpeername(2)	sys_getpeername
53	socketpair	socketpair(2)	sys_socketpair
54	setsockopt	setsockopt(2)	sys_setsockopt
55	getsockopt	getsockopt(2)	sys_getsockopt
56	clone	clone(2)	sys_clone
57	fork	fork(2)	sys_fork
58	vfork	vfork(2)	sys_vfork
59	execve	execve(2)	sys_execve
60	exit	exit(2)	sys_exit
61	wait4	wait4(2)	sys_wait4
62	kill	kill(2)	sys_kill
63	uname	uname(2)	sys_newuname
64	semget	semget(2)	sys_semget
65	semop	semop(2)	sys_semop
66	semctl	semctl(2)	sys_semctl
67	shmdt	shmdt(2)	sys_shmdt
68	msgget	msgget(2)	sys_msgget
69	msgsnd	msgsnd(2)	sys_msgsnd
70	msgrcv	msgrcv(2)	sys_msgrcv
71	msgctl	msgctl(2)	sys_msgctl
72	fcntl	fcntl(2)	sys_fcntl
73	flock	flock(2)	sys_flock
74	fsync	fsync(2)	sys_fsync
75	fdatasync	fdatasync(2)	sys_fdatasync
76	truncate	truncate(2)	sys_truncate
77	ftruncate	ftruncate(2)	sys_ftruncate
78	getdents	getdents(2)	sys_getdents
79	getcwd	getcwd(2)	sys_getcwd
80	chdir	chdir(2)	sys_chdir
81	fchdir	fchdir(2)	sys_fchdir
82	rename	rename(2)	sys_rename
83	mkdir	mkdir(2)	sys_mkdir
84	rmdir	rmdir(2)	sys_rmdir
85	creat	creat(2)	sys_creat
86	link	link(2)	sys_link
87	unlink	unlink(2)	sys_unlink
88	symlink	symlink(2)	sys_symlink
89	readlink	readlink(2)	sys_readlink
90	chmod	chmod(2)	sys_chmod
91	fchmod	fchmod(2)	sys_fchmod
92	chown	chown(2)	sys_chown
93	fchown	fchown(2)	sys_fchown
94	lchown	lchown(2)	sys_lchown
95	umask	umask(2)	sys_umask
96	gettimeofday	gettimeofday(2)	sys_gettimeofday
97	getrlimit	getrlimit(2)	sys_getrlimit
98	getrusage	getrusage(2)	sys_getrusage
99	sysinfo	sysinfo(2)	sys_sysinfo
100	times	times(2)	sys_times
101	ptrace	ptrace(2)	sys_ptrace
102	getuid	getuid(2)	sys_getuid
103	syslog	syslog(2)	sys_syslog
104	getgid	getgid(2)	sys_getgid
105	setuid	setuid(2)	sys_setuid
106	setgid	setgid(2)	sys_setgid
107	geteuid	geteuid(2)	sys_geteuid
108	getegid	getegid(2)	sys_getegid
109	setpgid	setpgid(2)	sys_setpgid
110	getppid	getppid(2)	sys_getppid
111	getpgrp	getpgrp(2)	sys_getpgrp
112	setsid	setsid(2)	sys_setsid
113	setreuid	setreuid(2)	sys_setreuid
114	setregid	setregid(2)	sys_setregid
115	getgroups	getgroups(2)	sys_getgroups
116	setgroups	setgroups(2)	sys_setgroups
117	setresuid	setresuid(2)	sys_setresuid
118	getresuid	getresuid(2)	sys_getresuid
119	setresgid	setresgid(2)	sys_setresgid
120	getresgid	getresgid(2)	sys_getresgid
121	getpgid	getpgid(2)	sys_getpgid
122	setfsuid	setfsuid(2)	sys_setfsuid
123	setfsgid	setfsgid(2)	sys_setfsgid
124	getsid	getsid(2)	sys_getsid
125	capget	capget(2)	sys_capget
126	capset	capset(2)	sys_capset
127	rt_sigpending	rt_sigpending(2)	sys_rt_sigpending
128	rt_sigtimedwait	rt_sigtimedwait(2)	sys_rt_sigtimedwait
129	rt_sigqueueinfo	rt_sigqueueinfo(2)	sys_rt_sigqueueinfo
130	rt_sigsuspend	rt_sigsuspend(2)	sys_rt_sigsuspend
131	sigaltstack	sigaltstack(2)	sys_sigaltstack
132	utime	utime(2)	sys_utime
133	mknod	mknod(2)	sys_mknod
134	uselib	uselib(2)	
135	personality	personality(2)	sys_personality
136	ustat	ustat(2)	sys_ustat
137	statfs	statfs(2)	sys_statfs
138	fstatfs	fstatfs(2)	sys_fstatfs
139	sysfs	sysfs(2)	sys_sysfs
140	getpriority	getpriority(2)	sys_getpriority
141	setpriority	setpriority(2)	sys_setpriority
142	sched_setparam	sched_setparam(2)	sys_sched_setparam
143	sched_getparam	sched_getparam(2)	sys_sched_getparam
144	sched_setscheduler	sched_setscheduler(2)	sys_sched_setscheduler
145	sched_getscheduler	sched_getscheduler(2)	sys_sched_getscheduler
146	sched_get_priority_max	sched_get_priority_max(2)	sys_sched_get_priority_max
147	sched_get_priority_min	sched_get_priority_min(2)	sys_sched_get_priority_min
148	sched_rr_get_interval	sched_rr_get_interval(2)	sys_sched_rr_get_interval
149	mlock	mlock(2)	sys_mlock
150	munlock	munlock(2)	sys_munlock
151	mlockall	mlockall(2)	sys_mlockall
152	munlockall	munlockall(2)	sys_munlockall
153	vhangup	vhangup(2)	sys_vhangup
154	modify_ldt	modify_ldt(2)	sys_modify_ldt
155	pivot_root	pivot_root(2)	sys_pivot_root
156	_sysctl	_sysctl(2)	sys_ni_syscall
157	prctl	prctl(2)	sys_prctl
158	arch_prctl	arch_prctl(2)	sys_arch_prctl
159	adjtimex	adjtimex(2)	sys_adjtimex
160	setrlimit	setrlimit(2)	sys_setrlimit
161	chroot	chroot(2)	sys_chroot
162	sync	sync(2)	sys_sync
163	acct	acct(2)	sys_acct
164	settimeofday	settimeofday(2)	sys_settimeofday
165	mount	mount(2)	sys_mount
166	umount2	umount2(2)	sys_umount
167	swapon	swapon(2)	sys_swapon
168	swapoff	swapoff(2)	sys_swapoff
169	reboot	reboot(2)	sys_reboot
170	sethostname	sethostname(2)	sys_sethostname
171	setdomainname	setdomainname(2)	sys_setdomainname
172	iopl	iopl(2)	sys_iopl
173	ioperm	ioperm(2)	sys_ioperm
174	create_module	create_module(2)	
175	init_module	init_module(2)	sys_init_module
176	delete_module	delete_module(2)	sys_delete_module
177	get_kernel_syms	get_kernel_syms(2)	
178	query_module	query_module(2)	
179	quotactl	quotactl(2)	sys_quotactl
180	nfsservctl	nfsservctl(2)	
181	getpmsg	getpmsg(2)	
182	putpmsg	putpmsg(2)	
183	afs_syscall	afs_syscall(2)	
184	tuxcall	tuxcall(2)	
185	security	security(2)	
186	gettid	gettid(2)	sys_gettid
187	readahead	readahead(2)	sys_readahead
188	setxattr	setxattr(2)	sys_setxattr
189	lsetxattr	lsetxattr(2)	sys_lsetxattr
190	fsetxattr	fsetxattr(2)	sys_fsetxattr
191	getxattr	getxattr(2)	sys_getxattr
192	lgetxattr	lgetxattr(2)	sys_lgetxattr
193	fgetxattr	fgetxattr(2)	sys_fgetxattr
194	listxattr	listxattr(2)	sys_listxattr
195	llistxattr	llistxattr(2)	sys_llistxattr
196	flistxattr	flistxattr(2)	sys_flistxattr
197	removexattr	removexattr(2)	sys_removexattr
198	lremovexattr	lremovexattr(2)	sys_lremovexattr
199	fremovexattr	fremovexattr(2)	sys_fremovexattr
200	tkill	tkill(2)	sys_tkill
201	time	time(2)	sys_time
202	futex	futex(2)	sys_futex
203	sched_setaffinity	sched_setaffinity(2)	sys_sched_setaffinity
204	sched_getaffinity	sched_getaffinity(2)	sys_sched_getaffinity
205	set_thread_area	set_thread_area(2)	
206	io_setup	io_setup(2)	sys_io_setup
207	io_destroy	io_destroy(2)	sys_io_destroy
208	io_getevents	io_getevents(2)	sys_io_getevents
209	io_submit	io_submit(2)	sys_io_submit
210	io_cancel	io_cancel(2)	sys_io_cancel
211	get_thread_area	get_thread_area(2)	
212	lookup_dcookie	lookup_dcookie(2)	
213	epoll_create	epoll_create(2)	sys_epoll_create
214	epoll_ctl_old	epoll_ctl_old(2)	
215	epoll_wait_old	epoll_wait_old(2)	
216	remap_file_pages	remap_file_pages(2)	sys_remap_file_pages
217	getdents64	getdents64(2)	sys_getdents64
218	set_tid_address	set_tid_address(2)	sys_set_tid_address
219	restart_syscall	restart_syscall(2)	sys_restart_syscall
220	semtimedop	semtimedop(2)	sys_semtimedop
221	fadvise64	fadvise64(2)	sys_fadvise64
222	timer_create	timer_create(2)	sys_timer_create
223	timer_settime	timer_settime(2)	sys_timer_settime
224	timer_gettime	timer_gettime(2)	sys_timer_gettime
225	timer_getoverrun	timer_getoverrun(2)	sys_timer_getoverrun
226	timer_delete	timer_delete(2)	sys_timer_delete
227	clock_settime	clock_settime(2)	sys_clock_settime
228	clock_gettime	clock_gettime(2)	sys_clock_gettime
229	clock_getres	clock_getres(2)	sys_clock_getres
230	clock_nanosleep	clock_nanosleep(2)	sys_clock_nanosleep
231	exit_group	exit_group(2)	sys_exit_group
232	epoll_wait	epoll_wait(2)	sys_epoll_wait
233	epoll_ctl	epoll_ctl(2)	sys_epoll_ctl
234	tgkill	tgkill(2)	sys_tgkill
235	utimes	utimes(2)	sys_utimes
236	vserver	vserver(2)	
237	mbind	mbind(2)	sys_mbind
238	set_mempolicy	set_mempolicy(2)	sys_set_mempolicy
239	get_mempolicy	get_mempolicy(2)	sys_get_mempolicy
240	mq_open	mq_open(2)	sys_mq_open
241	mq_unlink	mq_unlink(2)	sys_mq_unlink
242	mq_timedsend	mq_timedsend(2)	sys_mq_timedsend
243	mq_timedreceive	mq_timedreceive(2)	sys_mq_timedreceive
244	mq_notify	mq_notify(2)	sys_mq_notify
245	mq_getsetattr	mq_getsetattr(2)	sys_mq_getsetattr
246	kexec_load	kexec_load(2)	sys_kexec_load
247	waitid	waitid(2)	sys_waitid
248	add_key	add_key(2)	sys_add_key
249	request_key	request_key(2)	sys_request_key
250	keyctl	keyctl(2)	sys_keyctl
251	ioprio_set	ioprio_set(2)	sys_ioprio_set
252	ioprio_get	ioprio_get(2)	sys_ioprio_get
253	inotify_init	inotify_init(2)	sys_inotify_init
254	inotify_add_watch	inotify_add_watch(2)	sys_inotify_add_watch
255	inotify_rm_watch	inotify_rm_watch(2)	sys_inotify_rm_watch
256	migrate_pages	migrate_pages(2)	sys_migrate_pages
257	openat	openat(2)	sys_openat
258	mkdirat	mkdirat(2)	sys_mkdirat
259	mknodat	mknodat(2)	sys_mknodat
260	fchownat	fchownat(2)	sys_fchownat
261	futimesat	futimesat(2)	sys_futimesat
262	newfstatat	newfstatat(2)	sys_newfstatat
263	unlinkat	unlinkat(2)	sys_unlinkat
264	renameat	renameat(2)	sys_renameat
265	linkat	linkat(2)	sys_linkat
266	symlinkat	symlinkat(2)	sys_symlinkat
267	readlinkat	readlinkat(2)	sys_readlinkat
268	fchmodat	fchmodat(2)	sys_fchmodat
269	faccessat	faccessat(2)	sys_faccessat
270	pselect6	pselect6(2)	sys_pselect6
271	ppoll	ppoll(2)	sys_ppoll
272	unshare	unshare(2)	sys_unshare
273	set_robust_list	set_robust_list(2)	sys_set_robust_list
274	get_robust_list	get_robust_list(2)	sys_get_robust_list
275	splice	splice(2)	sys_splice
276	tee	tee(2)	sys_tee
277	sync_file_range	sync_file_range(2)	sys_sync_file_range
278	vmsplice	vmsplice(2)	sys_vmsplice
279	move_pages	move_pages(2)	sys_move_pages
280	utimensat	utimensat(2)	sys_utimensat
281	epoll_pwait	epoll_pwait(2)	sys_epoll_pwait
282	signalfd	signalfd(2)	sys_signalfd
283	timerfd_create	timerfd_create(2)	sys_timerfd_create
284	eventfd	eventfd(2)	sys_eventfd
285	fallocate	fallocate(2)	sys_fallocate
286	timerfd_settime	timerfd_settime(2)	sys_timerfd_settime
287	timerfd_gettime	timerfd_gettime(2)	sys_timerfd_gettime
288	accept4	accept4(2)	sys_accept4
289	signalfd4	signalfd4(2)	sys_signalfd4
290	eventfd2	eventfd2(2)	sys_eventfd2
291	epoll_create1	epoll_create1(2)	sys_epoll_create1
292	dup3	dup3(2)	sys_dup3
293	pipe2	pipe2(2)	sys_pipe2
294	inotify_init1	inotify_init1(2)	sys_inotify_init1
295	preadv	preadv(2)	sys_preadv
296	pwritev	pwritev(2)	sys_pwritev
297	rt_tgsigqueueinfo	rt_tgsigqueueinfo(2)	sys_rt_tgsigqueueinfo
298	perf_event_open	perf_event_open(2)	sys_perf_event_open
299	recvmmsg	recvmmsg(2)	sys_recvmmsg
300	fanotify_init	fanotify_init(2)	sys_fanotify_init
301	fanotify_mark	fanotify_mark(2)	sys_fanotify_mark
302	prlimit64	prlimit64(2)	sys_prlimit64
303	name_to_handle_at	name_to_handle_at(2)	sys_name_to_handle_at
304	open_by_handle_at	open_by_handle_at(2)	sys_open_by_handle_at
305	clock_adjtime	clock_adjtime(2)	sys_clock_adjtime
306	syncfs	syncfs(2)	sys_syncfs
307	sendmmsg	sendmmsg(2)	sys_sendmmsg
308	setns	setns(2)	sys_setns
309	getcpu	getcpu(2)	sys_getcpu
310	process_vm_readv	process_vm_readv(2)	sys_process_vm_readv
311	process_vm_writev	process_vm_writev(2)	sys_process_vm_writev
312	kcmp	kcmp(2)	sys_kcmp
313	finit_module	finit_module(2)	sys_finit_module
314	sched_setattr	sched_setattr(2)	sys_sched_setattr
315	sched_getattr	sched_getattr(2)	sys_sched_getattr
316	renameat2	renameat2(2)	sys_renameat2
317	seccomp	seccomp(2)	sys_seccomp
318	getrandom	getrandom(2)	sys_getrandom
319	memfd_create	memfd_create(2)	sys_memfd_create
320	kexec_file_load	kexec_file_load(2)	sys_kexec_file_load
321	bpf	bpf(2)	sys_bpf
322	execveat	execveat(2)	sys_execveat
323	userfaultfd	userfaultfd(2)	sys_userfaultfd
324	membarrier	membarrier(2)	sys_membarrier
325	mlock2	mlock2(2)	sys_mlock2
326	copy_file_range	copy_file_range(2)	sys_copy_file_range
327	preadv2	preadv2(2)	sys_preadv2
328	pwritev2	pwritev2(2)	sys_pwritev2
329	pkey_mprotect	pkey_mprotect(2)	sys_pkey_mprotect
330	pkey_alloc	pkey_alloc(2)	sys_pkey_alloc
331	pkey_free	pkey_free(2)	sys_pkey_free
332	statx	statx(2)	sys_statx
333	io_pgetevents	io_pgetevents(2)	sys_io_pgetevents
334	rseq	rseq(2)	sys_rseq
424	pidfd_send_signal	pidfd_send_signal(2)	sys_pidfd_send_signal
425	io_uring_setup	io_uring_setup(2)	sys_io_uring_setup
426	io_uring_enter	io_uring_enter(2)	sys_io_uring_enter
427	io_uring_register	io_uring_register(2)	sys_io_uring_register
428	open_tree	open_tree(2)	sys_open_tree
429	move_mount	move_mount(2)	sys_move_mount
430	fsopen	fsopen(2)	sys_fsopen
431	fsconfig	fsconfig(2)	sys_fsconfig
432	fsmount	fsmount(2)	sys_fsmount
433	fspick	fspick(2)	sys_fspick
434	pidfd_open	pidfd_open(2)	sys_pidfd_open
435	clone3	clone3(2)	sys_clone3
436	close_range	close_range(2)	sys_close_range
437	openat2	openat2(2)	sys_openat2
438	pidfd_getfd	pidfd_getfd(2)	sys_pidfd_getfd
439	faccessat2	faccessat2(2)	sys_faccessat2
440	process_madvise	process_madvise(2)	sys_process_madvise
441	epoll_pwait2	epoll_pwait2(2)	sys_epoll_pwait2
442	mount_setattr	mount_setattr(2)	sys_mount_setattr
443	quotactl_fd	quotactl_fd(2)	sys_quotactl_fd
444	landlock_create_ruleset	landlock_create_ruleset(2)	sys_landlock_create_ruleset
445	landlock_add_rule	landlock_add_rule(2)	sys_landlock_add_rule
446	landlock_restrict_self	landlock_restrict_self(2)	sys_landlock_restrict_self
447	memfd_secret	memfd_secret(2)	sys_memfd_secret
448	process_mrelease	process_mrelease(2)	sys_process_mrelease
449	futex_waitv	futex_waitv(2)	sys_futex_waitv
450	set_mempolicy_home_node	set_mempolicy_home_node(2)	sys_set_mempolicy_home_node
451	cachestat	cachestat(2)	sys_cachestat
452	fchmodat2	fchmodat2(2)	sys_fchmodat2
453	map_shadow_stack	map_shadow_stack(2)	sys_map_shadow_stack
454	futex_wake	futex_wake(2)	sys_futex_wake
455	futex_wait	futex_wait(2)	sys_futex_wait
456	futex_requeue	futex_requeue(2)	sys_futex_requeue`

var skipList = []string{
	"runtime.mallocgc",
	"runtime.gopanic",
	"runtime.typeAssert",
	"runtime.mapaccess1_fast64",
	"runtime.mapaccess1_fast64",
	"runtime.concatstring3",
	"runtime.panicwrap",
	"runtime.morestack_noctxt.abi0",
	"runtime.growslice",
	"runtime.makeslice",
	"runtime.newobject",
	"runtime.newobject",
	"runtime.slicebytetostring",
	"runtime.memmove",
	"runtime.lock2",
	"runtime.unlock2",
	"runtime.gcWriteBarrier2",
	"runtime.printstring",

	"internal/godebug.(*Setting).Value",
	"internal/godebug.(*Setting).IncNonDefault",

	"runtime.ifaceeq",        // ??
	"runtime.deferreturn",    // ??
	"runtime.resolveNameOff", // ??
	"runtime.resolveTypeOff", // ??
}

// map of syscall wrappers and mapped to the argument position they expect the syscall number on
var wrapList = map[string]int{
	"syscall.Syscall.abi0":                         0,
	"syscall.rawVforkSyscall.abi0":                 0,
	"syscall.rawSyscallNoError.abi0":               0,
	"runtime/internal/syscall.Syscall6":            0,
	"golang.org/x/sys/unix.Syscall.abi0":           0,
	"golang.org/x/sys/unix.RawSyscallNoError.abi0": 0,
}

type Sym struct {
	Name       string
	Addr       uint64
	AbsAddr    uint64
	Size       uint64
	Prog       *elf.Prog
	Syscalls   map[int64]struct{}
	References map[*Sym]struct{}

	AllSyscalls   map[int64]struct{}
	AllReferences map[*Sym]struct{}
	collected     bool
}

type Syscalls struct {
	syms     []*Sym
	syscalls map[int64]string
	skipList map[uint64]struct{}
	wrappers map[uint64]int
}

func (s *Syscalls) Find(filename string) error {
	// load syscalls
	scmap := make(map[int64]string)
	sclines := strings.Split(strings.Replace(syscalls, "\r", "", -1), "\n")
	for _, line := range sclines {
		sc := strings.Split(line, "\t")
		if len(sc) < 2 {
			continue
		}
		sci, err := strconv.ParseInt(sc[0], 10, 64)
		if err != nil {
			continue
		}
		scmap[sci] = sc[1]
	}
	scmap[-1] = "DYNAMIC"
	s.syscalls = scmap

	f, err := elf.Open(filename)
	if err != nil {
		return fmt.Errorf("open elf: %w", err)
	}
	defer f.Close()

	syms, err := f.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return fmt.Errorf("failed go get symbols: %w", err)
	}

	err = s.analyzeSymbols(f, syms)
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return fmt.Errorf("failed go analyze symbols: %w", err)
	}

	syms, err = f.DynamicSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return fmt.Errorf("failed go get dynamic symbols: %w", err)
	}

	err = s.analyzeSymbols(f, syms)
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return fmt.Errorf("failed go analyze symbols: %w", err)
	}

	// Fill skiplist and wrappers
	s.skipList = make(map[uint64]struct{})
	s.wrappers = make(map[uint64]int)
	for _, sym := range s.syms {
		if slices.Contains(skipList, sym.Name) {
			s.skipList[sym.AbsAddr] = struct{}{}
		}
		if arg, ok := wrapList[sym.Name]; ok {
			s.wrappers[sym.AbsAddr] = arg
		}
	}

	for _, sym := range s.syms {
		s.disasmFunc(sym)
	}

	for _, sym := range s.syms {
		s.recurse(sym)
	}
	s.report(s.reduce())

	return nil
}

func (s *Syscalls) analyzeSymbols(f *elf.File, syms []elf.Symbol) error {
	for _, sym := range syms {
		if elf.ST_TYPE(sym.Info) != elf.STT_FUNC {
			continue
		}

		for _, prog := range f.Progs {
			if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
				continue
			}
			if prog.Vaddr < sym.Value && sym.Value < prog.Vaddr+prog.Memsz {
				s.syms = append(s.syms, &Sym{
					Name:          sym.Name,
					Addr:          sym.Value - prog.Vaddr,
					AbsAddr:       sym.Value,
					Size:          sym.Size,
					Prog:          prog,
					Syscalls:      map[int64]struct{}{},
					References:    map[*Sym]struct{}{},
					AllSyscalls:   map[int64]struct{}{},
					AllReferences: map[*Sym]struct{}{},
				})
				break
			}
		}
	}
	return nil
}

// lookup finds the symbol name containing addr.
func (s *Syscalls) lookup(addr uint64) (name string, base uint64) {
	i := sort.Search(len(s.syms), func(i int) bool { return addr < s.syms[i].AbsAddr })
	if i > 0 {
		s := s.syms[i-1]
		if s.AbsAddr != 0 && s.AbsAddr <= addr && addr < s.AbsAddr+uint64(s.Size) {
			return s.Name, s.AbsAddr
		}
	}
	return "", 0
}

// lookup finds the symbol name containing addr.
func (s *Syscalls) lookupSym(addr uint64) *Sym {
	i := sort.Search(len(s.syms), func(i int) bool { return addr < s.syms[i].AbsAddr })
	if i > 0 {
		sym := s.syms[i-1]
		if sym.AbsAddr != 0 && sym.AbsAddr <= addr && addr < sym.AbsAddr+uint64(sym.Size) {
			return sym
		}
	}
	return nil
}

func (s *Syscalls) disasmFunc(sym *Sym) error {
	// address := sym.Value - prog.Vaddr + prog.Off
	dump := false
	// syscall.Syscall.abi0
	if sym.Name == "XXsyscall.rawVforkSyscall.abi0" { // "golang.org/x/sys/unix.RawSyscallNoError.abi0" { // "runtime/internal/syscall.Syscall6" { // "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf.BPF" { // "golang.org/x/sys/unix.Syscall.abi0" { // syscall.Syscall.abi0
		dump = true
		log.Printf("----- %s", sym.Name)
		log.Printf("----- %.2X", sym.Addr)
		log.Printf("----- %.2X", sym.AbsAddr)
		log.Printf("----- OFF %d", sym.Prog.Off)
		log.Printf("%+v", sym)
	}

	data := make([]byte, sym.Size)
	_, err := sym.Prog.ReadAt(data, int64(sym.Addr)) // -sym.Prog.Off
	if err != nil {
		return fmt.Errorf("failed go get data: %w", err)
	}
	index := 0

	if dump {
		log.Printf("%X", data)
	}

	arg := int64(-1)
	syscallNo := int64(-1)
	for index < len(data) {
		instruction, err := x86asm.Decode(data[index:], 64)
		if dump {
			log.Printf("%X", data[index:index+instruction.Len])
			log.Printf("%.2X %s", sym.AbsAddr+uint64(index), x86asm.GoSyntax(instruction, uint64(int64(sym.AbsAddr)+int64(index)), nil))
			for i, a := range instruction.Args {
				log.Printf("%d %T %s", i, a, a)
			}
		}
		if err != nil || instruction.Len == 0 || instruction.Op == 0 {
			index++ // skip 1 byte, see https://github.com/golang/go/blob/master/src/cmd/internal/objfile/disasm.go#L309C2-L309C46
			continue
		}
		if instruction.Op == x86asm.SYSCALL {
			if syscallNo < 0 || syscallNo > 10000 {
				sym.Syscalls[-1] = struct{}{}
				log.Printf("skipping syscall %d in %s", syscallNo, sym.Name)
				index += instruction.Len
				continue
			}
			log.Printf("syscall: %s (%d) (%d)", s.syscalls[syscallNo], instruction.Opcode, syscallNo)
			sym.Syscalls[syscallNo] = struct{}{}
		}
		// This is probably not enough
		if instruction.Op == x86asm.MOV && (instruction.Args[0] == x86asm.RAX || instruction.Args[0] == x86asm.EAX) {
			// setting EAX also clears RAX
			if i, ok := instruction.Args[1].(x86asm.Imm); ok {
				syscallNo = int64(i)
			}
		}

		if instruction.Op == x86asm.MOV && instruction.Args[0] == x86asm.RDI {
			if i, ok := instruction.Args[1].(x86asm.Imm); ok {
				if dump {
					log.Printf("RDI SET TO %d", int64(i))
				}
			}
		}

		if instruction.Op == x86asm.MOV { // QMOV?
			if mem, ok := instruction.Args[0].(x86asm.Mem); ok {
				if dump {
					log.Printf("MEM %+v", mem)
				}
				if mem.Base == x86asm.RSP {
					if i, ok := instruction.Args[1].(x86asm.Imm); ok {
						arg = int64(i)
					}
				}
			}
		}
		// log.Printf("%s", x86asm.GoSyntax(instruction, uint64(int64(sym.Prog.Vaddr)+int64(index)), nil))
		// if instruction.Op == x86asm.CALL {
		if a, ok := instruction.Args[0].(x86asm.Rel); ok && a != 0 {
			addr := uint64(int64(sym.AbsAddr) + int64(index) + int64(instruction.Len) + int64(a))

			if _, ok := s.skipList[addr]; ok {
				index += instruction.Len
				continue
			}

			// test hardcoded
			// if addr == 0x6b28e0 || addr == 0x4E6720 || addr == 0x407080 || addr == 0x6B2960 || addr == 0x4E5E00 {
			if _, ok := s.wrappers[addr]; ok {
				// This is golang.org/x/sys/unix.Syscall.abi0, we need to check first argument (held in RSP+Reg(0))
				if arg >= 0 {
					log.Printf("registered syscall %d %s", arg, s.syscalls[arg])
					sym.Syscalls[arg] = struct{}{}
					index += instruction.Len
					continue
				}
			}

			ref := s.lookupSym(addr)
			if ref == nil {
				index += instruction.Len
				continue
			}
			sym.References[ref] = struct{}{}
			if dump {
				log.Printf("YY> %s", ref.Name)
			}
		}
		// if a, ok := instruction.Args[1].(x86asm.Rel); ok && a != 0 {
		// 	addr := int64(sym.AbsAddr) + int64(index) + int64(instruction.Len) + int64(a)
		// 	ref := s.lookupSym(uint64(addr))
		// 	if ref == nil {
		// 		index += instruction.Len
		// 		continue
		// 	}
		// 	sym.References[ref] = struct{}{}
		// 	// log.Printf("YY> %s", name)
		// }
		// }

		// if a, ok := instruction.Args[1].(x86asm.Rel); ok {
		// 	addr := int64(sym.AbsAddr) + int64(index) + int64(instruction.Len) + int64(a)
		// 	name, xaddr := s.lookup(uint64(addr))
		// 	if xaddr == 0 {
		// 		index += instruction.Len
		// 		continue
		// 	}
		// 	log.Printf("YY> %s", name)
		// }
		// x86asm.GoSyntax()
		index += instruction.Len
	}
	return nil
}

func (s *Sym) PackageName() string {
	parts := strings.Split(s.Name, "/")
	last := strings.Split(parts[len(parts)-1], ".")
	return strings.Join(append(parts[:len(parts)-1], last[0]), "/")
}

type Ext struct {
	PackageName string
	Syscalls    map[int64]struct{}
	References  map[*Sym]struct{}
	Packages    map[string]struct{}
}

func (s *Syscalls) recurse(sym *Sym) {
	if sym.collected {
		return
	}
	sym.collected = true
	maps.Copy(sym.AllSyscalls, sym.Syscalls)
	maps.Copy(sym.AllReferences, sym.References)
	for other := range sym.References {
		s.recurse(other)
		maps.Copy(sym.AllSyscalls, other.AllSyscalls)
		maps.Copy(sym.AllReferences, other.AllReferences)
	}
}

func (s *Syscalls) reduce() map[string]*Ext {
	packages := make(map[string]*Ext)
	var ok bool
	var pkg *Ext
	for _, sym := range s.syms {
		pkgName := sym.PackageName()
		if pkg, ok = packages[pkgName]; !ok {
			pkg = &Ext{
				PackageName: pkgName,
				Syscalls:    make(map[int64]struct{}),
				References:  make(map[*Sym]struct{}),
				Packages:    map[string]struct{}{},
			}
			packages[pkgName] = pkg
		}
		maps.Copy(pkg.Syscalls, sym.AllSyscalls)
		// maps.Copy(pkg.References, sym.References)
		pkg.References[sym] = struct{}{}

		for p := range sym.AllReferences {
			pkg.Packages[p.PackageName()] = struct{}{}
		}
	}
	return packages
}

func SortToArray[T any, E cmp.Ordered](in map[E]T) []T {
	keys := slices.Collect(maps.Keys(in))
	slices.Sort(keys)
	res := make([]T, len(keys))
	for i, k := range keys {
		res[i] = in[k]
	}
	return res
}

func SortKeys[T any, E cmp.Ordered](in map[E]T) []E {
	keys := slices.Collect(maps.Keys(in))
	slices.Sort(keys)
	return keys
}

func MapMapKeys[X cmp.Ordered, Y any, E any](in map[X]Y, fn func(X) E) []E {
	res := make([]E, 0, len(in))
	for i := range in {
		res = append(res, fn(i))
	}
	return res
}

func MapArray[X any, E any](in []X, fn func(X) E) []E {
	res := make([]E, len(in))
	for i, x := range in {
		res[i] = fn(x)
	}
	return res
}

func SortKeysFn[T any, E comparable](in map[E]T, fn func(E, E) int) []E {
	keys := slices.Collect(maps.Keys(in))
	slices.SortFunc(keys, fn)
	return keys
}

func (s *Syscalls) recprint(sym *Sym, spc string, l map[*Sym]struct{}, pkg string) {
	if _, ok := l[sym]; ok {
		fmt.Printf("%s %s [abr]\n", spc, sym.Name)
		return
	}
	l[sym] = struct{}{}
	// Skip uninteresting ones
	if len(sym.AllSyscalls) == 0 {
		return
	}
	fmt.Printf("%s %s\n", spc, sym.Name)
	for n := range sym.Syscalls {
		fmt.Printf("%s @%s\n", spc, s.syscalls[n])
	}
	// Skip uninteresting ones
	if len(sym.AllSyscalls) == len(sym.Syscalls) {
		return
	}
	// Skip other packages
	if sym.PackageName() != pkg {
		for n := range sym.AllSyscalls {
			fmt.Printf("%s  @%s\n", spc, s.syscalls[n])
		}
		return
	}
	for o := range sym.References {
		s.recprint(o, spc+" ", l, pkg)
	}
}

func (s *Syscalls) report(packages map[string]*Ext) {
	pks := SortToArray(packages)
	for _, pkg := range pks {
		lookup := map[*Sym]struct{}{}
		if len(pkg.Syscalls) == 0 {
			continue
		}
		fmt.Printf("\n[ %s ]\n", pkg.PackageName)
		for _, syscallNo := range SortKeys(pkg.Syscalls) {
			fmt.Printf(" syscall (%d) %s\n", syscallNo, s.syscalls[syscallNo])
		}
		for _, sym := range SortKeysFn(pkg.References, func(sym1 *Sym, sym2 *Sym) int {
			return cmp.Compare(sym1.Name, sym2.Name)
		}) {
			// fmt.Printf(" ref %s\n", sym.Name)
			s.recprint(sym, "", lookup, pkg.PackageName)
		}
		for _, pkg := range SortKeys(pkg.Packages) {
			fmt.Printf(" imports %s\n", pkg)
		}
	}
}

func main() {
	s := &Syscalls{}
	err := s.Find(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
}
