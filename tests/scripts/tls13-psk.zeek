# @TEST-EXEC: zeek -C -r $TRACES/tls13_psk_succesfull.pcap $SCRIPTS/tls.zeek %INPUT
# @TEST-EXEC: mv tls.log tls_connections_succesfull.log
# @TEST-EXEC: zeek -C -r $TRACES/tls13_psk_unsuccesful.pcap $SCRIPTS/tls.zeek %INPUT
# @TEST-EXEC: mv tls.log tls_connections_unsuccesful.log
# @TEST-EXEC: btest-diff tls_connections_succesfull.log
# @TEST-EXEC: btest-diff tls_connections_unsuccesful.log
