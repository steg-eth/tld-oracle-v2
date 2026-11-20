  // Append this entry to the `algorithms` array in
  // test/dnssec-oracle/fixtures/algorithms.ts, after the RSASHA256Algorithm entry.
  //
  // Vector is RFC 5702 section 6.2, the sibling of the RSASHA256 vector already in this file
  // (which comes from section 6.1). Same `example.net` key owner, same
  // `www.example.net. 3600 IN A 192.0.2.91` record, same 2000 to 2030 validity, so it never
  // expires. Produced the same way as its neighbour:
  //
  //   dnskey  = DNSKEY rdata, digestable form
  //   signdata = RRSIG rdata without the signature, then the canonical RRset
  //   signature = the RRSIG signature field
  [
    'RSASHA512Algorithm',
    [
      // example.net.  3600  IN  DNSKEY  256 3 10 AwEAAdHoNTOW+et86KuJOWRDp1pndvwb6Y83nSVXXyLA
      //               3DLroROUkN6X0O6pnWnjJQujX/AyhqFDxj13tOnD9u/1kTg7cV6rklMrZDtJCQ5PCl/D7QNP
      //               sgVsMu1J2Q8gpMpztNFLpPBz1bWXjDtaR7ZQBlZ3PFY12ZTSncorffcGmhOL  ; id = 3740
      '0x0100030a03010001d1e8353396f9eb7ce8ab89396443a75a6776fc1be98f379d25575f22c0dc32eba1139490de97d0eea99d69e3250ba35ff03286a143c63d77b4e9c3f6eff591383b715eab92532b643b49090e4f0a5fc3ed034fb2056c32ed49d90f20a4ca73b4d14ba4f073d5b5978c3b5a47b6500656773c5635d994d29dca2b7df7069a138b',
      // www.example.net.  3600  IN  A  192.0.2.91
      '0x00010a0300000e1070dbd880386d43800e9c076578616d706c65036e65740003777777076578616d706c65036e6574000001000100000e100004c000025b',
      // www.example.net.  3600  IN  RRSIG  A 10 3 3600 20300101000000 20000101000000 3740
      //                   example.net. tsb4wnjRUDnB1BUi+t6TMTXThjVnG+eCkWqjvvjhzQL1d0YRoOe0Cbxr
      //                   VDYd0xDtsuJRaeUw1ep94PzEWzr0iGYgZBWm/zpq+9fOuagYJRfDqfReKBzMweOLDiNa
      //                   8iP5g9vMhpuv6OPlvpXwm9Sa9ZXIbNl1MBGk0fthPgxdDLw=
      '0xb6c6f8c278d15039c1d41522fade933135d38635671be782916aa3bef8e1cd02f5774611a0e7b409bc6b54361dd310edb2e25169e530d5ea7de0fcc45b3af48866206415a6ff3a6afbd7ceb9a8182517c3a9f45e281cccc1e38b0e235af223f983dbcc869bafe8e3e5be95f09bd49af595c86cd9753011a4d1fb613e0c5d0cbc',
    ],
  ],
