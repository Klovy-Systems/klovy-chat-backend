//! Nagłówek z user-agentem przesyłanym jawnie przez oficjalny klient webowy.
//! Proxy/CDN często nie przekazują standardowego `User-Agent` do API.
pub const CLIENT_USER_AGENT_HEADER: &str = "x-klovy-user-agent";
