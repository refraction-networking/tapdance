use mio::Token;
use std::collections::{HashMap, VecDeque};

// 'I' for 'item type'; the traditional 'T' could be confused for 'token'.
pub struct TokenMap<I>
{
    map: HashMap<Token, I>,
    available_tokens: VecDeque<UniqTok>,
    largest_token: usize,
}

// Do NOT implement Clone or Copy.
#[derive(Debug)]
pub struct UniqTok
{
    tok: Token,
}
impl UniqTok
{
    // Note that this new() is NOT pub. Only TokenMap can make them.
    fn new(val: usize) -> UniqTok
    {
        UniqTok { tok: Token::from(val) }
    }
    pub fn val(&self) -> Token { self.tok }
}

impl<I> TokenMap<I>
{
    pub fn with_initial_capacity(cap: usize) -> TokenMap<I>
    {
        let mut the_map = TokenMap::<I> {
            map: HashMap::new(),
            available_tokens: VecDeque::with_capacity(cap+1),
            largest_token: cap };
        for i in 1..cap+1 {
            the_map.available_tokens.push_back(UniqTok::new(i));
        }
        the_map
    }
    pub fn insert(&mut self, item: I) -> UniqTok
    {
        if let Some(tok) = self.available_tokens.pop_front() {
            self.map.insert(tok.val(), item);
            tok
        } else {
            self.largest_token += 1;
            let new_tok = UniqTok::new(self.largest_token);
            self.map.insert(new_tok.val(), item);
            new_tok
        }
    }
    pub fn remove(&mut self, tok: UniqTok)
    {
        if self.map.remove(&tok.val()).is_some() {
            self.available_tokens.push_back(tok);
        }
    }
    pub fn contains_key(&self, key: &Token) -> bool
    {
        self.map.contains_key(key)
    }
    pub fn get_mut(&mut self, key: &Token) -> Option<&mut I>
    {
        self.map.get_mut(key)
    }
}

//TODO: unit tests!
