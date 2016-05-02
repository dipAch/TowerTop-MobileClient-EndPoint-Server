/* --------------------------------------*
 * @author   [Dipankar Achinta]          |
 * @type     [JSON API ENDPOINT SERVER]  |
 * @platform [Node.js]                   |
 * @date     [10/05/2015]                |
 * @language [JavaScript]                |
 * --------------------------------------*
 */

// Import necessary Node.js modules
var http = require('http'), mysql = require('mysql'), url = require('url'), bcrypt = require('bcryptjs'), config = require('./server_config/config');

// HTTP status codes to be sent along with the JSON response
var SUCCESS = { code: 200, message: "OK" };
var BAD_REQ = { code: 400, message: "BAD REQUEST" };
var RESOURCE_NOT_FOUND = { code: 404, message: "RESOURCE NOT FOUND" };
var INTERNAL_SERVER_ERR = { code: 500, message: "INTERNAL SERVER ERROR" };
var SERVICE_UNAVAILABLE = { code: 503, message: "SERVICE UNAVAILABLE" };
// Below: console.log() utility constants, to be used for monitoring server response statuses
var DB_CONN_ERR = "DB CONNECTION FAILED";
var MYSQL_QUERY_ERR = "QUERY FAILED";
var QUERY_SUCC = "QUERY EXECUTED";
var SERVICE_ERR = "COULD NOT SERVICE REQUEST";
var AUTH_SUCC = "AUTHENTICATION SUCCESSFUL";
var AUTH_FAILURE = "AUTHENTICATION FAILED";
var PASSWORD_INVALID = "PASSWORD INVALID";
var ZEROTH_USER = 0;
var BCRYPT_COMPARE_ERR = "BCRYPT ERROR";
var INVALID_EMAIL = "INVALID EMAIL";
var INVALID_PWD = "INVALID PASSWORD";
var EMPTY_RESULT_SET = "EMPTY RESULT SET";
var UPDATE_FAIL = "COULD NOT PERFORM UPDATE OPERATION";
var UPDATE_SUCC = "UPDATE PERFORMED SUCCESSFULLY";
var USER_CREATE_SUCC = "USER WAS ADDED SUCCESSFULLY";
var USER_CREATE_FAIL = "COULD NOT ADD USER";
var LOCAL_COMPARE_SUCC = 0;
var LOGIN_ACTION = "LOGIN";
var UPDATE_PASSWORD_ACTION = "PASSWORD_UPDATE";
var FETCH_SUCC = "FETCH SUCCESSFUL";
var FETCH_FAILURE = "FETCH FAILED";
var EMPTY = 0;
var START_IDX = 0;
var JSON_NEWLINE = "\n"

// Helpers to identify the status of a request,
// Can be moved to an external file?...Food for thought
// ----------------------------------------------------
/* Helper to send the final JSON response object
 * Takes in 3 Parameters,
 * res -> the Response Object, status_code -> HTTP status object, json_data -> the JSON response to be sent
 */
function send_response(res, status_code, json_output) {
	res.writeHead(status_code, { "Content-Type": "application/json" });
	res.end(JSON.stringify(json_output) + JSON_NEWLINE);
}

/* Helper to indicate service success
 * Takes in 2 Parameters,
 * res -> the Response Object, json_data -> the JSON response to be sent
 */
function service_success(res, json_data) {
	if(!json_data.error) {
		json_data.error = false;
	}
	if(!json_data.message) {
		json_data.message = SUCCESS.message;
	}
	send_response(res, SUCCESS.code, json_data);
}

/* Helper to indicate bad request from client
 * Takes in 1 Parameter,
 * res -> the Response Object
 */
function bad_request(res) {
	var json_data = { error: true, message: BAD_REQ.message };
	send_response(res, BAD_REQ.code, json_data);
}

/* Helper to indicate resource not found
 * Takes in 1 Parameter,
 * res -> the Response Object
 */
function resource_not_found(res) {
	var json_data = { error: true, message: RESOURCE_NOT_FOUND.message };
	send_response(res, RESOURCE_NOT_FOUND.code, json_data);
}

/* Helper to indicate internal error ( server error )
 * Takes in 1 Parameter,
 * res -> the Response Object
 */
function internal_server_err(res) {
	var json_data = { error: true, message: INTERNAL_SERVER_ERR.message };
	send_response(res, INTERNAL_SERVER_ERR.code, json_data);
}

/* Helper to indicate service unavailable
 * Takes in 1 Parameter,
 * res -> the Response Object
 */
function service_unavailable(res) {
	var json_data = { error: true, message: SERVICE_UNAVAILABLE.message };
	send_response(res, SERVICE_UNAVAILABLE.code, json_data);
}

/*
 * Function to setup database client
 */
function setup_db() {
	// Initialize database object by specifying database credentials
	dbclient = mysql.createConnection({
		host: config.host(),
		user: config.user(),
		password: config.password(),
		database: config.database()
	});
	return dbclient;
}

/*
 * Function to connect to database after setting up database credentials
 */
function connect_db(initialized_dbclient) {
	// Connect to database with initialized credentials
	initialized_dbclient.connect(function(err, results) {
		// Handle any connection related errors and log to the console
		if(err) {
			console.log("-> MYSQL::CONNECT::ERROR::" + "[" + err.code + "]" + " - " + err.message);
			return DB_CONN_ERR;
		}
	});
	return initialized_dbclient;
}

/*
 * Function that performs authentication of a queried user,
 * This function provides the interface to actually query the underlying database
 */
function login_auth_api(req, res, established_dbclient, action) {
	action = typeof action !== 'undefined' ? UPDATE_PASSWORD_ACTION : LOGIN_ACTION;
	if(established_dbclient == DB_CONN_ERR) {
		console.log("-> NODE::SERVER::LOG - " + DB_CONN_ERR);
		internal_server_err(res);
		return;
	}
	// Perform database query with the established database connection
	established_dbclient.query("SELECT * FROM login WHERE email = '" + escapeRegExp(req.parsed_url_obj.query.email) + "'",
		function(err, rows) {
			// Handle any query related errors and log to the console
			if(err) {
				console.log("-> MYSQL::SELECT::ERROR::" + "[" + err.code + "]" + " - " + err.message);
				console.log("-> NODE::SERVER::LOG - " + MYSQL_QUERY_ERR);
				internal_server_err(res);
				return;
			}
			established_dbclient.end();
			if(rows.length > EMPTY) {
				if(action.localeCompare(LOGIN_ACTION) == LOCAL_COMPARE_SUCC) {
					valid_password(req, res, rows); // Check password for login
				} else {
					valid_password(req, res, rows, action); // Check password for updating it
				}			
				console.log("-> NODE::SERVER::LOG - " + QUERY_SUCC); // When we have a successful DB interaction
			} else {
				if(action.localeCompare(LOGIN_ACTION) == LOCAL_COMPARE_SUCC) {
					process_login_result(res, rows, false, false); // Email was incorrect
				} else {
					process_password_update(res, false); // Email was incorrect
				}			
				console.log("-> NODE::SERVER::LOG - " + EMPTY_RESULT_SET); // When empty result set is returned
			}
		}
	);
}

function valid_password(req, res, result_set, action) {
	action = typeof action !== 'undefined' ? UPDATE_PASSWORD_ACTION : LOGIN_ACTION;
	if(action.localeCompare(LOGIN_ACTION) == LOCAL_COMPARE_SUCC) {
		bcrypt.compare(escapeRegExp(req.parsed_url_obj.query.password), result_set[ZEROTH_USER].password, function(err, validity) {
			if(err) {
				console.log("-> NODE::SERVER::LOG - " + BCRYPT_COMPARE_ERR);
				internal_server_err(res);
				return;
			}
			process_login_result(res, result_set, validity, true);		
		});
	} else {
		bcrypt.compare(escapeRegExp(req.parsed_url_obj.query.oldpass), result_set[ZEROTH_USER].password, function(err, validity) {
			if(err) {
				console.log("-> NODE::SERVER::LOG - " + BCRYPT_COMPARE_ERR);
				internal_server_err(res);
				return;
			}
			perform_password_update_action(req, res, connect_db(setup_db()), validity);
		});
	}
}

/*
 * Function to process the returned result set from the database,
 * The final JSON output will be sent from here and handed over to minion functions
 */
function process_login_result(res, login_result, pass_validity, not_empty_set) {
	var output = null;
	if(not_empty_set) {
		// For debugging's sake
		debug_to_console(login_result);
		// Make appropriate JSON response body based on the retrieved data
		if(login_result.length > EMPTY && pass_validity) {
			var user_obj = { uid: login_result[ZEROTH_USER].user_id, role: login_result[ZEROTH_USER].role, email: login_result[ZEROTH_USER].email, first_name: login_result[ZEROTH_USER].first_name, last_name: login_result[ZEROTH_USER].last_name, address: login_result[ZEROTH_USER].address, state: login_result[ZEROTH_USER].state, mobile: login_result[ZEROTH_USER].mobile, prefer_state: login_result[ZEROTH_USER].prefer_state, prefer_tehsil: login_result[ZEROTH_USER].prefer_tehsil, prefer_village: login_result[ZEROTH_USER].prefer_village };
			output = { error: '', message: '', verdict: AUTH_SUCC , authenticated: true, user: user_obj };
		} else {
			output = { error: true, message: '', verdict: AUTH_FAILURE, authenticated: false, cause: INVALID_PWD };
		}
	} else{
		output = { error: true, message: '', verdict: AUTH_FAILURE, authenticated: false, cause: INVALID_EMAIL };
	}
	// send JSON response back to client
	service_success(res, output);
}

// Utility functions for checking if 'password' and 'email' parameters have been defined
function password_defined(query_hash) {
	if(typeof query_hash.password == "undefined" || query_hash.password == '') {
		return true;
	}
	return false;
}

function email_defined(query_hash) {
	if(typeof query_hash.email == "undefined" || query_hash.email == '') {
		return true;
	}
	return false;
}

function debug_to_console(returned_rows) {
	// Print retrieved data back to the console...Just for the sake of program stepping
	if(returned_rows.length > EMPTY) {
		for(var i = START_IDX; i < returned_rows.length; i++) {
			console.log("<-->Requested:__User#{uid: " + returned_rows[i].user_id + ", role: " + returned_rows[i].role + ", email: " + returned_rows[i].email + ", first_name: " + returned_rows[i].first_name + ", last_name: " + returned_rows[i].last_name + ", address: " + returned_rows[i].address + ", state: " + returned_rows[i].state + ", mobile: " + returned_rows[i].mobile + "}__<-->");
		}
	}
}

// Get client IP address from request object
get_client_address = function (req) {
    return (req.headers['x-forwarded-for'] || '').split(',')[0] || req.connection.remoteAddress;
};

/*
 * Profile Update Functionality
 */

// Utility functions for checking if 'fname', 'lname', 'role', 'mobile', 'address', 'state' and 'pre_updated_email' parameters have been defined
function fname_defined(query_hash) {
	if(typeof query_hash.fname == "undefined" || query_hash.fname == '') {
		return true;
	}
	return false;
}

function lname_defined(query_hash) {
	if(typeof query_hash.lname == "undefined" || query_hash.lname == '') {
		return true;
	}
	return false;
}

function role_defined(query_hash) {
	if(typeof query_hash.role == "undefined" || query_hash.role == '') {
		return true;
	}
	return false;
}

function mobile_defined(query_hash) {
	if(typeof query_hash.mobile == "undefined" || query_hash.mobile == '') {
		return true;
	}
	return false;
}

function address_defined(query_hash) {
	if(typeof query_hash.address == "undefined" || query_hash.address == '') {
		return true;
	}
	return false;
}

function state_defined(query_hash) {
	if(typeof query_hash.state == "undefined" || query_hash.state == '') {
		return true;
	}
	return false;
}

function original_email_defined(query_hash) {
	if(typeof query_hash.original_email == "undefined" || query_hash.original_email == '') {
		return true;
	}
	return false;
}

function old_password_defined(query_hash) {
	if(typeof query_hash.oldpass == "undefined" || query_hash.oldpass == '') {
		return true;
	}
	return false;
}

function new_password_defined(query_hash) {
	if(typeof query_hash.newpass == "undefined" || query_hash.newpass == '') {
		return true;
	}
	return false;
}

function prefer_state_defined(query_hash) {
	if(typeof query_hash.prefer_state == "undefined" || query_hash.prefer_state == '') {
		return true;
	}
	return false;
}

function prefer_tehsil_defined(query_hash) {
	if(typeof query_hash.prefer_tehsil == "undefined" || query_hash.prefer_tehsil == '') {
		return true;
	}
	return false;
}

function prefer_village_defined(query_hash) {
	if(typeof query_hash.prefer_village == "undefined" || query_hash.prefer_village == '') {
		return true;
	}
	return false;
}

// Escape Utility
function escapeRegExp(string) {
    return string.replace(/([#;*~`'"?^=!:${}()<>|\[\]\/\\])/g, "\\$1");
}

/*
 * Function that performs profile update of a queried user,
 * This function provides the interface to actually query the underlying database
 */
function profile_update_api(req, res, established_dbclient) {
	if(established_dbclient == DB_CONN_ERR) {
		console.log("-> NODE::SERVER::LOG - " + DB_CONN_ERR);
		internal_server_err(res);
		return;
	}
	// Perform database query with the established database connection
	established_dbclient.query("SELECT * FROM login WHERE email = '" + escapeRegExp(req.parsed_url_obj.query.original_email) + "'",
		function(err, rows) {
			// Handle any query related errors and log to the console
			if(err) {
				console.log("-> MYSQL::SELECT::ERROR::" + "[" + err.code + "]" + " - " + err.message);
				console.log("-> NODE::SERVER::LOG - " + MYSQL_QUERY_ERR);
				internal_server_err(res);
				return;
			}
			if(rows.length > EMPTY) {
				perform_profile_update(req, res, established_dbclient, rows[ZEROTH_USER].user_id);
				console.log("-> NODE::SERVER::LOG - " + QUERY_SUCC); // When we have a successful DB interaction
			} else {
				process_profile_update(res, false);
				console.log("-> NODE::SERVER::LOG - " + EMPTY_RESULT_SET); // When empty result set is returned
			}
		}
	);
}

/*
 * Function to make the change on the selected user object
 */
function perform_profile_update(req, res, established_dbclient, profile_id) {
	var query_obj = req.parsed_url_obj.query;
	var user_email = escapeRegExp(query_obj.email);
	var user_fname = escapeRegExp(query_obj.fname);
	var user_lname = escapeRegExp(query_obj.lname);
	var user_addr = escapeRegExp(query_obj.address);
	var user_state = escapeRegExp(query_obj.state);
	var user_mobile = escapeRegExp(query_obj.mobile);
	// Perform database query with the established database connection
	established_dbclient.query("UPDATE login SET email = '" + user_email + "', first_name = '" + user_fname + "', last_name = '" + user_lname + "', address = '" + user_addr.replace(new RegExp(escapeRegExp("%20"), 'g'), " ") + "', state = '" + user_state + "', mobile = '" + user_mobile + "' WHERE user_id = '" + profile_id + "'",
		function(err, rows) {
			// Handle any query related errors and log to the console
			if(err) {
				console.log("-> MYSQL::UPDATE::ERROR::" + "[" + err.code + "]" + " - " + err.message);
				console.log("-> NODE::SERVER::LOG - " + MYSQL_QUERY_ERR);
				internal_server_err(res);
				return;
			}
			established_dbclient.end();
			if(rows.affectedRows > EMPTY) {
				process_profile_update(res, true);
				console.log("-> NODE::SERVER::LOG - " + QUERY_SUCC); // When we have a successful DB interaction
			} else {
				process_profile_update(res, false);
				console.log("-> NODE::SERVER::LOG - " + UPDATE_FAIL); // When no rows were affected
			}
		}
	);
}

/*
 * Function to process the returned result set from the database,
 * The final JSON output will be sent from here and handed over to minion functions
 */
function process_profile_update(res, was_updated) {
	var output = null;
	if(was_updated) {
		// Make appropriate JSON response body based on the retrieved data
		output = { error: false, message: '', verdict: UPDATE_SUCC, updated: true };
	} else{
		output = { error: true, message: '', verdict: UPDATE_FAIL, updated: false };
	}
	// send JSON response back to client
	service_success(res, output);
}

/*
 * Function that allows to create a new user object in the database
 */
function create_user_api(req, res, established_dbclient) {
	if(established_dbclient == DB_CONN_ERR) {
		console.log("-> NODE::SERVER::LOG - " + DB_CONN_ERR);
		internal_server_err(res);
		return;
	}
	var query_obj = req.parsed_url_obj.query;
	var user_role = escapeRegExp(query_obj.role);
	var user_pass = escapeRegExp(query_obj.password);
	var user_email = escapeRegExp(query_obj.email);
	var user_fname = escapeRegExp(query_obj.fname);
	var user_lname = escapeRegExp(query_obj.lname);
	var user_addr = escapeRegExp(query_obj.address);
	var user_state = escapeRegExp(query_obj.state);
	var user_mobile = escapeRegExp(query_obj.mobile);
	bcrypt.genSalt(10, function(err, salt) {
		bcrypt.hash(user_pass, salt, function(err, hash) {
			// Perform database query with the established database connection
			established_dbclient.query("INSERT INTO login (role, password, email, first_name, last_name, address, state, mobile) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", [user_role, hash, user_email, user_fname, user_lname, user_addr.replace(new RegExp(escapeRegExp("%20"), 'g'), " "), user_state, user_mobile],
				function(err, rows) {
					// Handle any query related errors and log to the console
					if(err) {
						console.log("-> MYSQL::INSERT::ERROR::" + "[" + err.code + "]" + " - " + err.message);
						console.log("-> NODE::SERVER::LOG - " + MYSQL_QUERY_ERR);
						internal_server_err(res);
						return;
					}
					established_dbclient.end();
					if(rows.affectedRows > EMPTY) {
						process_create_user(res, true);
						console.log("-> NODE::SERVER::LOG - " + QUERY_SUCC); // When we have a successful DB interaction
					} else {
						process_create_user(res, false);
						console.log("-> NODE::SERVER::LOG - " + USER_CREATE_FAIL); // When no rows were affected
					}
				}
			);
		});
	});
}

/*
 * Function to process the returned result set from the database,
 * The final JSON output will be sent from here and handed over to minion functions
 */
function process_create_user(res, was_created) {
	var output = null;
	if(was_created) {
		// Make appropriate JSON response body based on the retrieved data
		output = { error: false, message: '', verdict: USER_CREATE_SUCC, created: true };
	} else{
		output = { error: true, message: '', verdict: USER_CREATE_FAIL, created: false };
	}
	// send JSON response back to client
	service_success(res, output);
}

/*
 * Function that interacts with the database and updates the selected user's password
 */
function perform_password_update_action(req, res, established_dbclient, pass_validity) {
	if(established_dbclient == DB_CONN_ERR) {
		console.log("-> NODE::SERVER::LOG - " + DB_CONN_ERR);
		internal_server_err(res);
		return;
	}
	if(pass_validity) {
		var user_new_pass = escapeRegExp(req.parsed_url_obj.query.newpass);
		var user_email = escapeRegExp(req.parsed_url_obj.query.email);
		bcrypt.genSalt(10, function(err, salt) {
			bcrypt.hash(user_new_pass, salt, function(err, hash) {
				// Perform database query with the established database connection
				established_dbclient.query("UPDATE login SET password = '" + hash + "' WHERE email = '" + user_email + "'",
					function(err, rows) {
						// Handle any query related errors and log to the console
						if(err) {
							console.log("-> MYSQL::UPDATE::ERROR::" + "[" + err.code + "]" + " - " + err.message);
							console.log("-> NODE::SERVER::LOG - " + MYSQL_QUERY_ERR);
							internal_server_err(res);
							return;
						}
						established_dbclient.end();
						if(rows.affectedRows > EMPTY) {
							process_password_update(res, true);
							console.log("-> NODE::SERVER::LOG - " + QUERY_SUCC); // When we have a successful DB interaction
						} else {
							process_password_update(res, false);
							console.log("-> NODE::SERVER::LOG - " + UPDATE_FAIL); // When no rows were affected
						}
					}
				);
			});
		});
	} else {
		established_dbclient.end();
		process_password_update(res, false); // Old password was incorrect
	}
}

/*
 * Function to send process' password update status.
 * Whether the update was successful or not
 */
function process_password_update(res, was_updated) {
	var output = null;
	if(was_updated) {
		// Make appropriate JSON response body based on the retrieved data
		output = { error: false, message: '', verdict: UPDATE_SUCC, updated: true };
	} else{
		output = { error: true, message: '', verdict: UPDATE_FAIL, updated: false };
	}
	// send JSON response back to client
	service_success(res, output);
}

/*
 * Function to fetch a user object from database based on email, role and mobile number
 */
function admin_user_fetch_api(req, res, established_dbclient) {
	if(established_dbclient == DB_CONN_ERR) {
		console.log("-> NODE::SERVER::LOG - " + DB_CONN_ERR);
		internal_server_err(res);
		return;
	}
	// Perform database query with the established database connection
	established_dbclient.query("SELECT * FROM login WHERE email = '" + escapeRegExp(req.parsed_url_obj.query.email) + "' AND role = '" + escapeRegExp(req.parsed_url_obj.query.role) + "'",
		function(err, rows) {
			// Handle any query related errors and log to the console
			if(err) {
				console.log("-> MYSQL::SELECT::ERROR::" + "[" + err.code + "]" + " - " + err.message);
				console.log("-> NODE::SERVER::LOG - " + MYSQL_QUERY_ERR);
				internal_server_err(res);
				return;
			}
			established_dbclient.end();
			if(rows.length > EMPTY) {
				process_admin_user_fetch(res, rows, true);	
				console.log("-> NODE::SERVER::LOG - " + QUERY_SUCC); // When we have a successful DB interaction
			} else {
				process_admin_user_fetch(res, rows, false);
				console.log("-> NODE::SERVER::LOG - " + EMPTY_RESULT_SET); // When empty result set is returned
			}
		}
	);
}

function process_admin_user_fetch(res, login_result, not_empty_set) {
	var output = null;
	if(not_empty_set) {
		// Make appropriate JSON response body based on the retrieved data
		var user_obj = { uid: login_result[ZEROTH_USER].user_id, role: login_result[ZEROTH_USER].role, email: login_result[ZEROTH_USER].email, first_name: login_result[ZEROTH_USER].first_name, last_name: login_result[ZEROTH_USER].last_name, address: login_result[ZEROTH_USER].address, state: login_result[ZEROTH_USER].state, mobile: login_result[ZEROTH_USER].mobile };
		output = { error: '', message: '', verdict: FETCH_SUCC , authenticated: true, fetched: true, user: user_obj };	
	} else{
		output = { error: true, message: '', verdict: FETCH_FAILURE, authenticated: false, fetched: false };
	}
	// send JSON response back to client
	service_success(res, output);
}

/*
 * Function that performs role update of a queried user,
 * This function provides the interface to actually query the underlying database
 */
function role_update_api(req, res, established_dbclient) {
	if(established_dbclient == DB_CONN_ERR) {
		console.log("-> NODE::SERVER::LOG - " + DB_CONN_ERR);
		internal_server_err(res);
		return;
	}
	// Perform database query with the established database connection
	established_dbclient.query("SELECT * FROM login WHERE email = '" + escapeRegExp(req.parsed_url_obj.query.email) + "'",
		function(err, rows) {
			// Handle any query related errors and log to the console
			if(err) {
				console.log("-> MYSQL::SELECT::ERROR::" + "[" + err.code + "]" + " - " + err.message);
				console.log("-> NODE::SERVER::LOG - " + MYSQL_QUERY_ERR);
				internal_server_err(res);
				return;
			}
			if(rows.length > EMPTY) {
				perform_role_update(req, res, established_dbclient);
				console.log("-> NODE::SERVER::LOG - " + QUERY_SUCC); // When we have a successful DB interaction
			} else {
				process_role_update(res, false);
				console.log("-> NODE::SERVER::LOG - " + EMPTY_RESULT_SET); // When empty result set is returned
			}
		}
	);
}

/*
 * Function to make the change on the selected user object, in this case the role
 */
function perform_role_update(req, res, established_dbclient) {
	var query_obj = req.parsed_url_obj.query;
	var user_role = escapeRegExp(query_obj.role);
	var user_email = escapeRegExp(query_obj.email);
	// Perform database query with the established database connection
	established_dbclient.query("UPDATE login SET role = '" + user_role + "' WHERE email = '" + user_email + "'",
		function(err, rows) {
			// Handle any query related errors and log to the console
			if(err) {
				console.log("-> MYSQL::UPDATE::ERROR::" + "[" + err.code + "]" + " - " + err.message);
				console.log("-> NODE::SERVER::LOG - " + MYSQL_QUERY_ERR);
				internal_server_err(res);
				return;
			}
			established_dbclient.end();
			if(rows.affectedRows > EMPTY) {
				process_role_update(res, true);
				console.log("-> NODE::SERVER::LOG - " + QUERY_SUCC); // When we have a successful DB interaction
			} else {
				process_role_update(res, false);
				console.log("-> NODE::SERVER::LOG - " + UPDATE_FAIL); // When no rows were affected
			}
		}
	);
}

/*
 * Function to process the returned result set from the database,
 * The final JSON output will be sent from here and handed over to minion functions
 */
function process_role_update(res, was_updated) {
	var output = null;
	if(was_updated) {
		// Make appropriate JSON response body based on the retrieved data
		output = { error: false, message: '', verdict: UPDATE_SUCC, updated: true };
	} else{
		output = { error: true, message: '', verdict: UPDATE_FAIL, updated: false };
	}
	// send JSON response back to client
	service_success(res, output);
}

/*
 * Function that performs preference update of a queried user,
 * This function provides the interface to actually query the underlying database
 */
function preference_update_api(req, res, established_dbclient) {
	if(established_dbclient == DB_CONN_ERR) {
		console.log("-> NODE::SERVER::LOG - " + DB_CONN_ERR);
		internal_server_err(res);
		return;
	}
	// Perform database query with the established database connection
	established_dbclient.query("SELECT * FROM login WHERE email = '" + escapeRegExp(req.parsed_url_obj.query.email) + "'",
		function(err, rows) {
			// Handle any query related errors and log to the console
			if(err) {
				console.log("-> MYSQL::SELECT::ERROR::" + "[" + err.code + "]" + " - " + err.message);
				console.log("-> NODE::SERVER::LOG - " + MYSQL_QUERY_ERR);
				internal_server_err(res);
				return;
			}
			if(rows.length > EMPTY) {
				perform_preference_update(req, res, established_dbclient);
				console.log("-> NODE::SERVER::LOG - " + QUERY_SUCC); // When we have a successful DB interaction
			} else {
				process_preference_update(res, false);
				console.log("-> NODE::SERVER::LOG - " + EMPTY_RESULT_SET); // When empty result set is returned
			}
		}
	);
}

/*
 * Function to make the change on the selected user object, in this case the preference state, tehsil and village
 */
function perform_preference_update(req, res, established_dbclient) {
	var query_obj = req.parsed_url_obj.query;
	var user_prefer_state = escapeRegExp(query_obj.prefer_state);
	var user_prefer_tehsil = escapeRegExp(query_obj.prefer_tehsil);
	var user_prefer_village = escapeRegExp(query_obj.prefer_village);
	var user_email = escapeRegExp(query_obj.email);
	// Perform database query with the established database connection
	established_dbclient.query("UPDATE login SET prefer_state = '" + user_prefer_state + "', prefer_tehsil = '" + user_prefer_tehsil + "', prefer_village = '" + user_prefer_village + "' WHERE email = '" + user_email + "'",
		function(err, rows) {
			// Handle any query related errors and log to the console
			if(err) {
				console.log("-> MYSQL::UPDATE::ERROR::" + "[" + err.code + "]" + " - " + err.message);
				console.log("-> NODE::SERVER::LOG - " + MYSQL_QUERY_ERR);
				internal_server_err(res);
				return;
			}
			established_dbclient.end();
			if(rows.affectedRows > EMPTY) {
				process_preference_update(res, true);
				console.log("-> NODE::SERVER::LOG - " + QUERY_SUCC); // When we have a successful DB interaction
			} else {
				process_preference_update(res, false);
				console.log("-> NODE::SERVER::LOG - " + UPDATE_FAIL); // When no rows were affected
			}
		}
	);
}

/*
 * Function to process the returned result set from the database,
 * The final JSON output will be sent from here and handed over to minion functions
 */
function process_preference_update(res, was_updated) {
	var output = null;
	if(was_updated) {
		// Make appropriate JSON response body based on the retrieved data
		output = { error: false, message: '', verdict: UPDATE_SUCC, updated: true };
	} else{
		output = { error: true, message: '', verdict: UPDATE_FAIL, updated: false };
	}
	// send JSON response back to client
	service_success(res, output);
}

/*
 * Function that performs profile update of the admin account,
 * This function provides the interface to actually query the underlying database
 */
function admin_profile_update_api(req, res, established_dbclient) {
	if(established_dbclient == DB_CONN_ERR) {
		console.log("-> NODE::SERVER::LOG - " + DB_CONN_ERR);
		internal_server_err(res);
		return;
	}
	// Perform database query with the established database connection
	established_dbclient.query("SELECT * FROM login WHERE email = '" + escapeRegExp(req.parsed_url_obj.query.original_email) + "'",
		function(err, rows) {
			// Handle any query related errors and log to the console
			if(err) {
				console.log("-> MYSQL::SELECT::ERROR::" + "[" + err.code + "]" + " - " + err.message);
				console.log("-> NODE::SERVER::LOG - " + MYSQL_QUERY_ERR);
				internal_server_err(res);
				return;
			}
			if(rows.length > EMPTY) {
				perform_admin_profile_update(req, res, established_dbclient, rows[ZEROTH_USER].user_id);
				console.log("-> NODE::SERVER::LOG - " + QUERY_SUCC); // When we have a successful DB interaction
			} else {
				process_admin_profile_update(res, false);
				console.log("-> NODE::SERVER::LOG - " + EMPTY_RESULT_SET); // When empty result set is returned
			}
		}
	);
}

/*
 * Function to make the change on the selected user object
 */
function perform_admin_profile_update(req, res, established_dbclient, profile_id) {
	var query_obj = req.parsed_url_obj.query;
	var user_email = escapeRegExp(query_obj.email);
	var user_role = escapeRegExp(query_obj.role);
	var user_fname = escapeRegExp(query_obj.fname);
	var user_lname = escapeRegExp(query_obj.lname);
	var user_addr = escapeRegExp(query_obj.address);
	var user_state = escapeRegExp(query_obj.state);
	var user_mobile = escapeRegExp(query_obj.mobile);
	// Perform database query with the established database connection
	established_dbclient.query("UPDATE login SET role = '" + user_role + "', email = '" + user_email + "', first_name = '" + user_fname + "', last_name = '" + user_lname + "', address = '" + user_addr.replace(new RegExp(escapeRegExp("%20"), 'g'), " ") + "', state = '" + user_state + "', mobile = '" + user_mobile + "' WHERE user_id = '" + profile_id + "'",
		function(err, rows) {
			// Handle any query related errors and log to the console
			if(err) {
				console.log("-> MYSQL::UPDATE::ERROR::" + "[" + err.code + "]" + " - " + err.message);
				console.log("-> NODE::SERVER::LOG - " + MYSQL_QUERY_ERR);
				internal_server_err(res);
				return;
			}
			established_dbclient.end();
			if(rows.affectedRows > EMPTY) {
				process_admin_profile_update(res, true);
				console.log("-> NODE::SERVER::LOG - " + QUERY_SUCC); // When we have a successful DB interaction
			} else {
				process_admin_profile_update(res, false);
				console.log("-> NODE::SERVER::LOG - " + UPDATE_FAIL); // When no rows were affected
			}
		}
	);
}

/*
 * Function to process the returned result set from the database,
 * The final JSON output will be sent from here and handed over to minion functions
 */
function process_admin_profile_update(res, was_updated) {
	var output = null;
	if(was_updated) {
		// Make appropriate JSON response body based on the retrieved data
		output = { error: false, message: '', verdict: UPDATE_SUCC, updated: true };
	} else{
		output = { error: true, message: '', verdict: UPDATE_FAIL, updated: false };
	}
	// send JSON response back to client
	service_success(res, output);
}

/*
 * Function callback that listens for requests,
 * Runs when the server is started
 */
function handle_incoming_request(req, res) {
	// Put request details to console, to log the information
	console.log("-> NODE::INCOMING::REQUEST - " + get_client_address(req));
	// Parse the incoming request to redirect it to the appropriate API::Endpoint
	req.parsed_url_obj = url.parse(req.url, true);
	// Check and validate the parsed request
	// If service type is 'login' then expects parsed url pathname to be '/login.json'
	if(req.parsed_url_obj.pathname == '/login.json') {
		// Expects a 'email' and 'password' parameter: Strictly needed
		if(req.parsed_url_obj.search == '' || Object.keys(req.parsed_url_obj.query).length != 2 || password_defined(req.parsed_url_obj.query) || email_defined(req.parsed_url_obj.query)) {
			console.log("-> NODE::SERVER::LOG - " + BAD_REQ.message);
			bad_request(res);
			return;
		}
		login_auth_api(req, res, connect_db(setup_db()));
	} else if(req.parsed_url_obj.pathname == '/profile.json') { // If service type is 'profile' then expects parsed url pathname to be '/profile.json'
		// Expects all the parameters required for the transaction
		if(req.parsed_url_obj.search == '' || Object.keys(req.parsed_url_obj.query).length != 7 || 
		   fname_defined(req.parsed_url_obj.query) || lname_defined(req.parsed_url_obj.query) ||
		   email_defined(req.parsed_url_obj.query) || mobile_defined(req.parsed_url_obj.query) || 
		   address_defined(req.parsed_url_obj.query) || state_defined(req.parsed_url_obj.query) || 
		   original_email_defined(req.parsed_url_obj.query)) {
			console.log("-> NODE::SERVER::LOG - " + BAD_REQ.message);
			bad_request(res);
			return;
		}
		// Perform Profile Update Operation
		profile_update_api(req, res, connect_db(setup_db()));
	} else if(req.parsed_url_obj.pathname == '/adminprofile.json') { // If service type is 'profile' then expects parsed url pathname to be '/profile.json'
		// Expects all the parameters required for the transaction
		if(req.parsed_url_obj.search == '' || Object.keys(req.parsed_url_obj.query).length != 8 || 
		   fname_defined(req.parsed_url_obj.query) || lname_defined(req.parsed_url_obj.query) ||
		   email_defined(req.parsed_url_obj.query) || mobile_defined(req.parsed_url_obj.query) || 
		   address_defined(req.parsed_url_obj.query) || state_defined(req.parsed_url_obj.query) || 
		   original_email_defined(req.parsed_url_obj.query) || role_defined(req.parsed_url_obj.query)) {
			console.log("-> NODE::SERVER::LOG - " + BAD_REQ.message);
			bad_request(res);
			return;
		}
		// Perform Admin Profile Update Operation
		admin_profile_update_api(req, res, connect_db(setup_db()));
	} else if(req.parsed_url_obj.pathname == '/createuser.json') { // If service type is 'createuser' then expects parsed url pathname to be '/createuser.json'
		// Expects all the parameters required for the transaction
		if(req.parsed_url_obj.search == '' || Object.keys(req.parsed_url_obj.query).length != 8 || 
		   fname_defined(req.parsed_url_obj.query) || lname_defined(req.parsed_url_obj.query) ||
		   email_defined(req.parsed_url_obj.query) || role_defined(req.parsed_url_obj.query) ||
		   mobile_defined(req.parsed_url_obj.query) || address_defined(req.parsed_url_obj.query) ||
		   state_defined(req.parsed_url_obj.query) || password_defined(req.parsed_url_obj.query)) {
			console.log("-> NODE::SERVER::LOG - " + BAD_REQ.message);
			bad_request(res);
			return;
		}
		// Perform Create User Operation
		create_user_api(req, res, connect_db(setup_db()));
	} else if(req.parsed_url_obj.pathname == '/updatepass.json') { // If service type is 'updatepass' then expects parsed url pathname to be '/updatepass.json'
		// Expects all the parameters required for the transaction
		if(req.parsed_url_obj.search == '' || Object.keys(req.parsed_url_obj.query).length != 3 || 
		   old_password_defined(req.parsed_url_obj.query) || new_password_defined(req.parsed_url_obj.query) ||
		   email_defined(req.parsed_url_obj.query)) {
			console.log("-> NODE::SERVER::LOG - " + BAD_REQ.message);
			bad_request(res);
			return;
		}
		// Perform password update operation through the login API (overloaded API)
		login_auth_api(req, res, connect_db(setup_db()), UPDATE_PASSWORD_ACTION);
	} else if(req.parsed_url_obj.pathname == '/fetchuserdetails.json') { // Endpoint for admin fetch user task
		// Expects all the parameters required for the transaction
		if(req.parsed_url_obj.search == '' || Object.keys(req.parsed_url_obj.query).length != 2 || role_defined(req.parsed_url_obj.query) || email_defined(req.parsed_url_obj.query)) {
			console.log("-> NODE::SERVER::LOG - " + BAD_REQ.message);
			bad_request(res);
			return;
		}
		admin_user_fetch_api(req, res, connect_db(setup_db()));
	} else if(req.parsed_url_obj.pathname == '/adminupdateuserrole.json') { // Endpoint for admin user role update task
		// Expects all the parameters required for the transaction
		if(req.parsed_url_obj.search == '' || Object.keys(req.parsed_url_obj.query).length != 2 || role_defined(req.parsed_url_obj.query) || email_defined(req.parsed_url_obj.query)) {
			console.log("-> NODE::SERVER::LOG - " + BAD_REQ.message);
			bad_request(res);
			return;
		}
		// Perform User Role Update Operation
		role_update_api(req, res, connect_db(setup_db()));
	} else if(req.parsed_url_obj.pathname == '/updatepreferences.json') { // Endpoint for updating or setting user preferences
		// Expects all the parameters required for the transaction
		if(req.parsed_url_obj.search == '' || Object.keys(req.parsed_url_obj.query).length != 4 || prefer_state_defined(req.parsed_url_obj.query) ||
		   prefer_tehsil_defined(req.parsed_url_obj.query) || prefer_village_defined(req.parsed_url_obj.query) || email_defined(req.parsed_url_obj.query)) {
			console.log("-> NODE::SERVER::LOG - " + BAD_REQ.message);
			bad_request(res);
			return;
		}
		// Perform Preference Update Operation
		preference_update_api(req, res, connect_db(setup_db()));
	} else {
		// For requests that cannot be either served or currently unavailable
		console.log("-> NODE::SERVER::LOG - " + SERVICE_ERR);
		service_unavailable(res);
		return;
	}
}

// Start server service
json_api_server = http.createServer(handle_incoming_request);
json_api_server.listen(8080, '127.0.0.1'); // Listen on port:8080 at http://localhost:8080, by default runs on loop back, i.e., '127.0.0.1' or on '192.168.2.124'
console.log("-> NODE::SERVER::RUNNING at http://127.0.0.1:8080");