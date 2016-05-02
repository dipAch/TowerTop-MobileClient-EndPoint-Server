// Import the required Node.js modules
var http = require("http"), mysql = require("mysql");

// Function to handle any incoming request and sending appropriate JSON response.
function handle_incoming_request(req, res) {
	// Logging request details on to the console
	console.log("NODE::JSON::SERVER::INCOMING - REQUEST: " + req.method + " " + req.url);
	// Parsing the request to identify the request type.
	if(req.url.substr(0, 11) == "/login.json" && req.url.length > 11) {
		extracted_creds = req.url.substr(12);
		console.log(extracted_creds);
		var params = extracted_creds.split("&");
		console.log(params);
		var cred = {};
		// var output = null;
		params.forEach(function(element) {
			cred[element.split("=")[0]] = element.split("=")[1];
		});
		console.log(cred);
		// Database related operations for login authentication
		dbclient = mysql.createConnection({
			host: "localhost",
			user: "root",
			password: "dipankar",
			database: "farmap"
		});
		// Connect database with above MySQL credentials
		dbclient.connect(function(err, results) {
			// Handle any connection related errors and log to the console
			if(err) {
				console.log("MYSQL::CONNECT::ERR" + "[" + err.code + "]" + " - " + err.message);
			}
		});	
		// Perform database query with the established database connection
		dbclient.query("SELECT role, password FROM login WHERE role = '" + cred.name + "' AND password = '" + cred.password + "'", function(err, rows) {
			var output = null;
			// Handle any query related errors and log to the console
			if(err) {
				console.log("MYSQL::SELECT::ERR" + "[" + err.code + "]" + " - " + err.message);
				return;
			}
			// Print retrieved data back to the console...Just for the sake of program stepping
			for(var i = 0; i < rows.length; i++) {
				console.log("--> name:" + rows[i].role + " -|- password: " + rows[i].password);
			}
			// Make appropriate JSON response body based on the retrieved data
			if(rows.length > 0) {
				output = { error: null, message: "User Authenticated", user: cred }
			} else {
				output = { error: true, message: "User not found" }
			}
			// send JSON response back to client
			//send_success(res, output);
			res.writeHead(200, { "Content-Type": "application/json" });
			res.end(JSON.stringify(output) + "\n");
		});
		dbclient.end();
	} else {
		// Respond to inappropriate request
		console.log("NODE::JSON::SERVER::ERROR - Cannot resolve request - " + req.url);
		//send_failure(res, 400, invalid_request("Bad Request"));
		res.writeHead(400, { "Content-Type": "application/json" });
		res.end(JSON.stringify({ error: true, message: "Bad Request" }) + "\n");
	}
}

/*
// Helper functions
function make_error(err, msg) {
	var e = new Error(msg);
	e.code = err;
	return e;
}

function send_success(res, json_output) {
	res.writeHead(200, { "Content-Type": "application/json" });
	//var output = { error: null, data: data };
	res.end(JSON.stringify(json_output) + "\n");
}

function send_failure(res, code, err) {
	//var str_err_code = (err.code) ? err.code : err.name;
	res.writeHead(err.code, { "Content-Type": "application/json" });
	res.end(JSON.stringify({ error: true, err_code: err.code, err_message: err.message}) + "\n");
}

function invalid_request(msg) {
	if(!msg) {
		msg = "The requested resource does not exist.";
	}
	return make_error(400, msg);
}
*/

// Start server service
var s = http.createServer(handle_incoming_request);
s.listen(8080);
console.log("NODE::JSON::SERVER::RUNNING at http://127.0.0.1:8080");