# TLS Log Alternative

This package provides a log alternative to the traditional ```ssl.log```, which is provided by Zeek by default. If you load this package, you will get one (or optionally two) additional log files that provide a lot more information about the TLS handshake.

Loading this script by default will create a new ```tls.log``` file. This file contains a lot of low-level details of the handshake. For more details, please see ```tls.zeek``` in ```scripts```, which has documentation for every field. Example log output:

```
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	server_version	client_version	cipher	client_ciphers	sni	ssl_client_exts	ssl_server_exts	ticket_lifetime_hint	server_certs	client_certs	ssl_established	dh_param_size	point_formats	client_curves	curve	orig_alpn	resp_alpn	alert	client_supported_versions	server_supported_version	psk_key_exchange_modes	client_key_share_groups	server_key_share_group	client_comp_methods	sigalgs	hashalgs
#types	time	string	addr	port	addr	port	count	count	count	vector[count]	vector[string]	vector[count]	vector[count]	count	vector[string]vector[string]	bool	count	vector[count]	vector[count]	count	vector[string]	vector[string]	vector[count]	vector[count]	count	vector[count]	vector[count]	count	vector[count]	vector[count]	vector[count]
1491407508.244862	C59DC42iW3polXuIef	192.168.6.240	65503	139.162.123.134	13443	32531	771	4866	49196,49200,159,52393,52392,52394,49195,49199,158,49188,49192,107,49187,49191,103,49162,49172,57,49161,49171,51,157,156,4866,4867,4865,61,60,53,47,255	-	11,10,35,13,22,23,43,45,40	40	-	--	F	-	0,1,2	29,23,25,24	-	-	-	-	32531,771,770,769	-	1,0	29	29	0	3,3,3,4,5,6,1,1,1,3,1,2,2,2,2	4,5,6,8,8,8,4,5,6,2,2,2,4,5,6
1491407512.852869	C3tAYa2eYDO4qZFDie	192.168.6.240	65504	139.162.123.134	13443	32531	771	4866	49196,49200,159,52393,52392,52394,49195,49199,158,49188,49192,107,49187,49191,103,49162,49172,57,49161,49171,51,157,156,4866,4867,4865,61,60,53,47,255	-	11,10,35,13,22,23,43,45,40,42,41	40,41--	-	F	-	0,1,2	29,23,25,24	-	-	-	-	32531,771,770,769	-	1,0	29	29	0	3,3,3,4,5,6,1,1,1,3,1,2,2,2,2	4,5,6,8,8,8,4,5,6,2,2,2,4,5,6
```

If you re-define the option ```TLSLog::log_certificates``` to true, you also get a second log file called ```tls_certificates.log```, which contains a base64-encoded version of all certificates that are sent over the wire.

By default, certificate hashes are provided as sha256. If you want to use a different hash algorithm, you can redef ```TLSLog::hash_function``` to a different hash function, e.g. to ```sha1_hash```.

The easiest way to install this pacjage is by using the package manager; just do

```
zkg install 0xxon/tls-log-alternative
```
