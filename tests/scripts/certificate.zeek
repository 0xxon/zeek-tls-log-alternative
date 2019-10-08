# @TEST-EXEC: zeek -r $TRACES/ecdhe.pcap $SCRIPTS/tls.zeek %INPUT
# @TEST-EXEC: btest-diff tls_certificates.log

redef TLSLog::hash_function = sha1_hash;
redef TLSLog::log_certificates = T;
