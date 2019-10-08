# @TEST-EXEC: zeek -r $TRACES/dhe.pcap $SCRIPTS/tls.zeek %INPUT
# @TEST-EXEC: cat tls.log > tls-all.log
# @TEST-EXEC: zeek -r $TRACES/ecdhe.pcap $SCRIPTS/tls.zeek %INPUT
# @TEST-EXEC: cat tls.log >> tls-all.log
# @TEST-EXEC: zeek -r $TRACES/ssl.v3.trace $SCRIPTS/tls.zeek %INPUT
# @TEST-EXEC: cat tls.log >> tls-all.log
# @TEST-EXEC: zeek -r $TRACES/tls1_1.pcap $SCRIPTS/tls.zeek %INPUT
# @TEST-EXEC: cat tls.log >> tls-all.log
# @TEST-EXEC: zeek -r $TRACES/dtls1_0.pcap $SCRIPTS/tls.zeek %INPUT
# @TEST-EXEC: cat tls.log >> tls-all.log
# @TEST-EXEC: zeek -r $TRACES/dtls1_2.pcap $SCRIPTS/tls.zeek %INPUT
# @TEST-EXEC: cat tls.log >> tls-all.log
# @TEST-EXEC: btest-diff tls-all.log

