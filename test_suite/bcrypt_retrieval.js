// Get the necessary Node.js modules
var bcrypt = require('bcryptjs'), mysql = require('mysql');
var user_role = 'fieldman';
var user_pass = 'atthefield';

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
		console.log("-> MYSQL::CONNECT::ERR::" + "[" + err.code + "]" + " - " + err.message);
	}
});	
// Perform database query with the established database connection
dbclient.query("SELECT password FROM login WHERE role = ?", [user_role], function(err, res) {
	// Handle any query related errors and log to the console
	if(err) {
		console.log("-> MYSQL::SELECT::ERR::" + "[" + err.code + "]" + " - " + err.message);
		return;
	}
	console.log(res);
	dbclient.end();
	console.log("-> Password: " + res[0].password);
	bcrypt.compare(user_pass, res[0].password, function(err, res) { // try using "undefined" and see what happens
		if(err) {
			console.log("-> BCRYPTJS::COMPARE::ERR::" + "[" + err.code + "]" + " - " + err.message);
			return;
		}
		console.log(res);
	})
});

console.log("-> Password retrieval put to work");