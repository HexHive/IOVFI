extern crate libc;
extern crate rand;

use rand::Rng;

unsafe fn my_memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if dest.is_null() || src.is_null() {
        return dest;
    }

    let mut idx: usize = 0;
    while idx < n {
        *dest.add(idx) = *src.add(idx);
        idx += 1;
    }
    return dest;
}

fn main() {
    let size: usize = rand::thread_rng().gen_range(1, 101);
    let mut dest: Vec<u8> = Vec::with_capacity(size);
    let mut src: Vec<u8> = Vec::with_capacity(size);
    for _i in 0..size {
        let data: u8 = rand::thread_rng().gen_range(0x41, 0x4c); // 'A' -- 'Z'
        src.push(data);
    }
    let p = dest.as_mut_ptr();

    unsafe {
        my_memcpy(p, src.as_ptr(), size);
//        dest = Vec::from_raw_parts(p, size, size);
        println!("{} -> {}\n", String::from_utf8(src).ok().expect("src conversion failed"),
                 String::from_utf8(dest).ok().expect("dest conversion failed"));
    }
}
