struct NlMessage<'a> {
    buf: &'a Vec<u8>,
}

impl<'a> NlMessage<'a> {
    pub fn new(buf: &'a mut Vec<u8>) -> Self {
        Self { buf }
    }
}
