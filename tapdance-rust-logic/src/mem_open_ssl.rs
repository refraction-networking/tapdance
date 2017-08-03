use std::os::raw::c_void;

//HACKY_CFG_NO_TEST_BEGIN

use c_api;

pub struct MemOpenSSL
{
    // An SSL* from C.
    ptr: *mut c_void,
    // Put raw data from the other side in here, and SSL_read() will decrypt it.
    membio_from_remote: *mut c_void,
    // SSL_write() writes encrypted output data into here. (Unused).
    membio_to_remote: *mut c_void,
}
impl MemOpenSSL
{
    pub fn new() -> MemOpenSSL
    {
        MemOpenSSL { ptr: 0 as *mut c_void,
                     membio_from_remote: c_api::c_new_membio(),
                     membio_to_remote: c_api::c_new_membio() }
    }
    pub fn ssl_read(&mut self, output: &mut [u8]) -> Result<usize, i32>
    {
        if self.ptr != 0 as *mut c_void { c_api::c_SSL_read(self.ptr, output) }
        else                            { Err(0) }
    }
    // Returns number of bytes successfully fed. May be [0, input.len()].
    pub fn feed_data_from_remote(&mut self, input: &[u8]) -> u32
    {
        let raw_fed = c_api::c_BIO_write(self.membio_from_remote, input);
        if raw_fed < 0 { 0 } else { raw_fed as u32 }
    }
    // SSL_pending can tell you 0 when SSL_read would read. If we want this
    // functionality, this struct needs a buffer to hold SSL_read results, so
    // this function can try directly and then report the buffer size. (Rather,
    // this fn should become a bool; if we need to be able to say the exact
    // size, the buffer could get huge). So, TODO? Or just remove?
//     pub fn num_readbytes_ready(&self) -> i32
//     {
//         c_api::c_SSL_pending(self.ptr as *const c_void)
//     }

    pub fn set_ssl_ptr(&mut self, ptr: *mut c_void)
    {
        if ptr == 0 as *mut c_void
        {
            error!("Tried to MemOpenSSL::set_ssl_ptr(0)! Not doing it!");
            return;
        }
        self.ptr = ptr;
    }
    pub fn membio_from_remote(&self) -> *mut c_void { self.membio_from_remote }
    pub fn membio_to_remote(&self) -> *mut c_void { self.membio_to_remote }
}
impl Drop for MemOpenSSL
{
    fn drop(&mut self)
    {
        if self.ptr == 0 as *mut c_void
        {
            // These are freed by SSL_free(), but if there is nothing to
            // SSL_free(), then we have to do it ourselves.
            c_api::c_BIO_free_all(self.membio_from_remote);
            c_api::c_BIO_free_all(self.membio_to_remote);
        }
        c_api::c_SSL_free(self.ptr); // no-op if 0
    }
}
//HACKY_CFG_NO_TEST_END*/





























// The destitute man's mock object. Only works because we never need a
// non-mocked version of this struct while testing.

/*//HACKY_CFG_YES_TEST_BEGIN

use std::collections::VecDeque;
const SSL_ERROR_WANT_READ: i32 = 2;

pub struct MemOpenSSL
{
    // Here in test land, every byte that gets fed into the BIO just gets
    // SSL_read() back out identically.
    buf: VecDeque<u8>,
    // For testing the case where the BIO doesn't want to accept everything we
    // feed it. Each feed_data_from_remote() will pop the front item and use it
    // as the limit. If the queue is empty, there is no limit.
    // accept that many bytes (and then this will go back to None).
    next_feed_accept: VecDeque<usize>,
}
impl MemOpenSSL
{
    pub fn new() -> MemOpenSSL
    {
        MemOpenSSL { buf: VecDeque::new(),
                     next_feed_accept: VecDeque::new() }
    }
    pub fn ssl_read(&mut self, output: &mut [u8]) -> Result<usize, i32>
    {
        if self.buf.is_empty() { Err(SSL_ERROR_WANT_READ) }
        else
        {
            let mut i = 0;
            while i < output.len() && !self.buf.is_empty()
            {
                output[i] = self.buf.pop_front().unwrap();
                i += 1;
            }
            Ok(i as usize)
        }
    }
    pub fn TESTONLY_buflen(&self) -> usize { self.buf.len() }
    pub fn TESTONLY_schedule_feed_accepts(&mut self, sizes: &[usize])
    {
        self.next_feed_accept.extend(sizes);
    }
    // Returns number of bytes successfully fed. May be [0, input.len()].
    pub fn feed_data_from_remote(&mut self, input: &[u8]) -> u32
    {
        if let Some(limit) = self.next_feed_accept.pop_front()
        {
            let real_limit = if limit > input.len() {input.len()} else {limit};
            self.buf.extend(input[..real_limit].iter());
            real_limit as u32
        }
        else
        {
            self.buf.extend(input.iter());
            input.len() as u32
        }
    }
    pub fn set_ssl_ptr(&mut self, ptr: *mut c_void)
    { panic!("NOT MOCKED"); }
    pub fn membio_from_remote(&self) -> *mut c_void
    { panic!("NOT MOCKED"); }
    pub fn membio_to_remote(&self) -> *mut c_void
    { panic!("NOT MOCKED"); }
}

//HACKY_CFG_YES_TEST_END*/