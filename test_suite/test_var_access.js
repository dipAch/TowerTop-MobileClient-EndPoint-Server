// Asynchronous File Operation: node.js
var fs = require('fs');

var TEST = "COULD REACH";

fs.open(
	'test_files/test.txt', 'r',
	function(err, handle) {
		if(err) {
			console.log("ERR_OP1: " + err.code + " [" + err.message + "]");
			return;
		}
		console.log("File opened successfully...");
		console.log("--> " + TEST);
		var buf = new Buffer(100000);
		fs.read(
			handle, buf, 0, 100000, null,
			function(err, length) {
				if(err) {
					console.log("ERR_OP2: " + err.code + " [" + err.message + "]");
					return;
				}
				console.log("--> " + TEST);
				console.log("File contents: ");
				console.log(buf.toString('utf8', 0, length));
				fs.close(
					handle,
					function() {
						console.log("--> " + TEST);
						console.log("File closed successfully!!");
					}
				);
			}
		);
	}
);

console.log("File load started...");