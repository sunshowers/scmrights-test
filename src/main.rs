// Sorry about the sheer lack of error handling.

use libc::{c_int, cmsghdr, size_t, AF_UNIX, SOCK_CLOEXEC, SOCK_SEQPACKET};
use std::{mem, os::raw::c_void};

fn main() {
    let (sender1, receiver1) = make_socketpair();
    println!("first sender: {}, receiver: {}", sender1, receiver1);

    let (sender2, receiver2) = make_socketpair();
    println!("second sender: {}, receiver: {}", sender2, receiver2);

    // Create a thread which will receive the receiving fd.
    let handle = std::thread::spawn(move || {
        receive_fd(receiver1);
    });

    // Send receiver2 to the other process.
    unsafe {
        let cmsg_length = std::mem::size_of::<c_int>();
        let cmsg_buffer = libc::malloc(CMSG_SPACE(cmsg_length)) as *mut cmsghdr;
        if cmsg_buffer.is_null() {
            panic!("Failed to allocate memory for cmsg_buffer");
        }

        let (cmsg_buffer, len) = make_cmsghdr(receiver2);
        println!("cmsg buffer: {:?}, len: {}", cmsg_buffer, len);

        // This isn't required on Linux but maybe is on illumos?
        let mut iov = libc::iovec {
            iov_base: &len as *const _ as *mut c_void,
            iov_len: mem::size_of_val(&len),
        };

        let msg = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut iov as *mut libc::iovec,
            msg_iovlen: 1,
            msg_control: cmsg_buffer as *mut libc::c_void,
            msg_controllen: len as MsgControlLen,
            msg_flags: 0,
        };

        println!("Sending fd: {:?}", msg);

        if libc::sendmsg(sender1, &msg, 0) < 0 {
            panic!(
                "Failed to send file descriptor: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    handle.join().unwrap();
}

fn make_socketpair() -> (c_int, c_int) {
    let mut results = [0, 0];

    // Create a socket pair.
    unsafe {
        if libc::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, &mut results[0]) < 0 {
            panic!(
                "Failed to create socket pair: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    (results[0], results[1])
}

fn make_cmsghdr(fd: i32) -> (*mut cmsghdr, size_t) {
    // Send 1 fd over.
    let cmsg_length = mem::size_of::<i32>();
    unsafe {
        let cmsg_buffer = libc::malloc(CMSG_SPACE(cmsg_length)) as *mut cmsghdr;
        if cmsg_buffer.is_null() {
            panic!("Failed to allocate memory for cmsg_buffer");
        }

        (*cmsg_buffer).cmsg_len = CMSG_LEN(cmsg_length) as MsgControlLen;
        (*cmsg_buffer).cmsg_level = libc::SOL_SOCKET;
        (*cmsg_buffer).cmsg_type = libc::SCM_RIGHTS;

        *(CMSG_DATA(cmsg_buffer) as *mut i32) = fd;

        (cmsg_buffer, CMSG_SPACE(cmsg_length))
    }
}

fn receive_fd(socket: i32) {
    // Receive the file descriptor.
    let cmsg_length = mem::size_of::<c_int>();

    unsafe {
        let cmsg_buffer = libc::malloc(CMSG_SPACE(cmsg_length)) as *mut cmsghdr;

        let mut msg = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: std::ptr::null_mut(),
            msg_iovlen: 0,
            msg_control: cmsg_buffer as *mut libc::c_void,
            msg_controllen: CMSG_SPACE(cmsg_length) as MsgControlLen,
            msg_flags: 0,
        };

        let res = libc::recvmsg(socket, &mut msg, 0);
        println!("Received result: {}", res);

        if res < 0 {
            panic!(
                "Failed to receive file descriptor: {}",
                std::io::Error::last_os_error()
            );
        }

        // Print the fd received.
        println!("Received fd: {:?}", msg);

        let cmsg_fds = CMSG_DATA(cmsg_buffer) as *const c_int;
        println!("Received fd: {}", *cmsg_fds);
    }
}

#[allow(non_snake_case)]
fn CMSG_ALIGN(length: size_t) -> size_t {
    (length + mem::size_of::<size_t>() - 1) & !(mem::size_of::<size_t>() - 1)
}

#[allow(non_snake_case)]
fn CMSG_SPACE(length: size_t) -> size_t {
    CMSG_ALIGN(length) + CMSG_ALIGN(mem::size_of::<cmsghdr>())
}

#[allow(non_snake_case)]
fn CMSG_LEN(length: size_t) -> size_t {
    CMSG_ALIGN(mem::size_of::<cmsghdr>()) + length
}

#[allow(non_snake_case)]
unsafe fn CMSG_DATA(cmsg: *mut cmsghdr) -> *mut c_void {
    (cmsg as *mut libc::c_uchar).add(CMSG_ALIGN(mem::size_of::<cmsghdr>())) as *mut c_void
}

#[cfg(target_env = "gnu")]
type MsgIovLen = size_t;

#[cfg(not(target_env = "gnu"))]
type MsgIovLen = libc::c_int;

#[cfg(target_env = "gnu")]
type MsgControlLen = size_t;

#[cfg(not(target_env = "gnu"))]
type MsgControlLen = libc::socklen_t;
