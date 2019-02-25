// === LOAD REQUIRED PACKAGES === //
var passport       =  require( 'passport' );
var BasicStrategy  =  require( 'passport-http' ).BasicStrategy;

// === BASIC AUTHENTICATION STRATEGY === //
passport.use(
	new BasicStrategy(
		function( username , password , done ) 
		{
			// === ATTEMPT TO RETRIEVE USER FROM DATABASE === //
			var user  =  db.findOne( username );
			
			// === IF USER IS FOUND, USERNAME MATCHES, AND PASSWORD MATCHES, AUTHENTICATE === //
			if ( user != null && username == user.username && password == user.password )
			{
				return done( null , { name: user.username } );
			}
			// === OTHERWISE FAIL === //
			else
			{
				return done( null , false );
			}
		}
	));

// === SEND WHETHER AUTHENTICATION FAILS OR NOT === //
exports.isAuthenticated  =  passport.authenticate( 'basic' , { session : false } );