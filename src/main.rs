// Sorry about the sheer lack of error handling.

use libc::{
    c_int, cmsghdr, size_t, AF_UNIX, CMSG_DATA, CMSG_LEN, CMSG_SPACE, SOCK_CLOEXEC, SOCK_SEQPACKET,
};
use std::{ffi::c_uint, mem, os::raw::c_void};

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
        let (cmsg_buffer, len) = make_cmsghdr(receiver2);
        println!("cmsg buffer: {:?}, len: {}", cmsg_buffer, len);

        let data_buffer = [0u8; 1024];

        // This isn't required on Linux but is on illumos.
        let mut iovec = [
            libc::iovec {
                iov_base: &len as *const _ as *mut c_void,
                iov_len: mem::size_of_val(&len),
            },
            libc::iovec {
                iov_base: data_buffer.as_ptr() as *mut c_void,
                iov_len: data_buffer.len(),
            },
        ];

        let msg = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: iovec.as_mut_ptr(),
            msg_iovlen: 2,
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

    // Send a message to the other process.
    let message = "Hello, world!";
    unsafe {
        if libc::send(sender2, message.as_ptr() as *const c_void, message.len(), 0) < 0 {
            panic!(
                "Failed to send message: {}",
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

fn make_cmsghdr(fd: i32) -> (*mut cmsghdr, c_uint) {
    // Send 1 fd over.
    let cmsg_length = mem::size_of::<c_int>() as c_uint;
    unsafe {
        let cmsg_buffer = libc::malloc(CMSG_SPACE(cmsg_length) as usize) as *mut cmsghdr;
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
    let cmsg_length = mem::size_of::<c_int>() as c_uint;

    unsafe {
        let cmsg_buffer = libc::malloc(CMSG_SPACE(cmsg_length) as usize) as *mut cmsghdr;

        let mut len = 0usize;
        let mut data_buffer = [0u8; 1024];

        let mut iovec = [
            libc::iovec {
                iov_base: &mut len as *mut _ as *mut c_void,
                iov_len: mem::size_of_val(&len),
            },
            libc::iovec {
                iov_base: data_buffer.as_mut_ptr() as *mut c_void,
                iov_len: data_buffer.len(),
            },
        ];

        let mut msg = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: iovec.as_mut_ptr(),
            msg_iovlen: 2,
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
        let fd = *cmsg_fds;
        println!("Received fd: {}", fd);

        // Receive the message.
        let mut buffer = [0u8; 1024];
        let res = libc::recv(fd, buffer.as_mut_ptr() as *mut c_void, buffer.len(), 0);

        println!(
            "Received message: {:?}",
            std::str::from_utf8(&buffer[..res as usize])
        );
    }
}

#[cfg(target_env = "gnu")]
type MsgControlLen = size_t;

#[cfg(not(target_env = "gnu"))]
type MsgControlLen = libc::socklen_t;
