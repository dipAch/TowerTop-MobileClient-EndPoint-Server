// Get the necessary Node.js modules
var bcrypt = require('bcryptjs'), mysql = require('mysql');
// This is where you have to set new values to insert different rows in the table.
var user_role = 'fieldman', user_pass = 'atthefield', user_email = 'sidd@nic.in', user_fname = 'Siddhant', user_lname = 'Sehgal';
var user_addr = 'B-331 Hira Nandani, Powai, Mumbai', user_state = 'Maharashtra', user_mobile = '09679052541';

bcrypt.genSalt(10, function(err, salt) {
    bcrypt.hash(user_pass, salt, function(err, hash) {
        // Store hash in your password DB.
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
		dbclient.query("INSERT INTO login (role, password, email, first_name, last_name, address, state, mobile) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", [user_role, hash, user_email, user_fname, user_lname, user_addr, user_state, user_mobile], function(err, res) {
			// Handle any query related errors and log to the console
			if(err) {
				console.log("-> MYSQL::SELECT::ERR::" + "[" + err.code + "]" + " - " + err.message);
				return;
			}
			dbclient.end();
			console.log("-> Row created successfully");
		});
	});
});

console.log("-> bcryptjs put to work");