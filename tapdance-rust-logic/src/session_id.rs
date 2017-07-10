use std::fmt;

#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub struct SessionId([u8; 16]);

impl SessionId
{
    pub fn new(id: &[u8]) -> SessionId
    {
        let mut x = [0; 16];
        if id.len() == 16 {
            x.clone_from_slice(id);
        } else {
            error!("Tried to clone a slice, supposedly containing a SessionId,
                    that wasn't 16 bytes! Using 0 for this session's ID
                    Contents: {:?}", id);
        }
        SessionId(x)
    }
}
impl fmt::Debug for SessionId
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        let &SessionId(x) = self;
        write!(f, "SessionId({:?})", x)
    }
}
impl fmt::Display for SessionId
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        let &SessionId(x) = self;
        let mut s = String::new();
        for n in &x {
            s = s + &format!("{:02x}", n);
        }
        write!(f, "{}", s)
    }
}
