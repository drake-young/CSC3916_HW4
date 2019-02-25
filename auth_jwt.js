// === LOAD REQUIRED PACKAGES === //
var passport     =  require( 'passport' );
var JwtStrategy  =  require( 'passport-jwt' ).Strategy;
var ExtractJwt   =  require( 'passport-jwt' ).ExtractJwt;
require( 'dotenv' ).load( );

// === PREPARE VARS FOR JWT STRATEGY === //
var opts             =  { };
opts.jwtFromRequest  =  ExtractJwt.fromAuthHeaderWithScheme( "jwt" );
opts.secretOrKey     =  process.env.SECRET_KEY;

// === AUTHENTICATE USING JWT STRATEGY === //
passport.use(
	new JwtStrategy(
		opts, 
		function( jwt_payload , done ) 
		{
			// === ATTEMPT TO EXTRACT USER VIA TOKEN === //
			var user = db.find( jwt_payload.id );

			// === IF FOUND, AUTHENTICATE === //
			if ( user )
				done( null , user );
			
			// === OTHERWISE FAIL === //
			else
				done( null , false );
		}
	));

// === EXPORTS === //
exports.isAuthenticated  =  passport.authenticate( 'jwt' , { session : false } );
exports.secret           =  opts.secretOrKey ;