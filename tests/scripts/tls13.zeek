# @TEST-EXEC: zeek -C -r $TRACES/nghttp2.pcap $SCRIPTS/tls.zeek %INPUT
# @TEST-EXEC: btest-diff tls.log
