// Config file for database access authorization
// To be kept separate
var HOST = 'localhost';
var USER = 'root';
var PASSWORD = 'dipankar';
var DATABASE = 'farmap';

// Make exports so that we can access the credentials from the other files as a module
exports.host = function() {
	return HOST;
}
exports.user = function() {
	return USER;
}
exports.password = function() {
	return PASSWORD;
}
exports.database = function() {
	return DATABASE;
}