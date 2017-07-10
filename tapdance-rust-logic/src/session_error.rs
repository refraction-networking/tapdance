use signalling::ErrorReasonS2C;

#[derive(Debug)]
pub enum SessionError
{
    ClientStream,   // Client's TLS stream (or underlying TCP) broke
    CovertStream,   // TCP connection to Squid broke
    ClientReported, // Client sent an ERROR proto
    ClientProtocol, // Client misbehaved, e.g. malformed proto
    StationInternal,// Station logic hit a bad state; probably a station bug
    ClientTimeout,  // After cleanly closing a stream, sayig expect reconnect,
                    // client took too long (30 seconds) to establish a new one.
    DecoyOverload,  // The client picked an overloaded decoy for this session.
}

impl SessionError
{
    pub fn to_string(&self) -> &'static str
    {
        match self {
            &SessionError::ClientStream => "client_stream",
            &SessionError::CovertStream => "covert_stream",
            &SessionError::ClientReported => "client_reported",
            &SessionError::ClientProtocol => "client_protocol",
            &SessionError::StationInternal => "station_internal",
            &SessionError::ClientTimeout => "client_timeout",
            &SessionError::DecoyOverload => "decoy_overload" }
    }
    pub fn to_s2c_proto_enum(&self) -> ErrorReasonS2C
    {
        match self {
            &SessionError::ClientStream => ErrorReasonS2C::CLIENT_STREAM,
            &SessionError::CovertStream => ErrorReasonS2C::COVERT_STREAM,
            &SessionError::ClientReported => ErrorReasonS2C::CLIENT_REPORTED,
            &SessionError::ClientProtocol => ErrorReasonS2C::CLIENT_PROTOCOL,
            &SessionError::StationInternal => ErrorReasonS2C::STATION_INTERNAL,
            &SessionError::ClientTimeout => ErrorReasonS2C::CLIENT_TIMEOUT,
            &SessionError::DecoyOverload => ErrorReasonS2C::DECOY_OVERLOAD }
    }
}
