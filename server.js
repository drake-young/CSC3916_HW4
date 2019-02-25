// === FROM EXTERNAL FILES === //
var express            =  require( 'express' );
var http               =  require( 'http' );
var bodyParser         =  require( 'body-parser' );
var passport           =  require( 'passport' );
var authController     =  require( './auth' );
var authJwtController  =  require( './auth_jwt' );
var jwt                =  require( 'jsonwebtoken' );
db                     =  require( './db' )( ); //global hack

// === CREATE THE APP === //
var app  =  express( );

// === SET UP BODY PARSER === //
app.use( bodyParser.json( ) );
app.use( bodyParser.urlencoded( { extended : false } ) );

// === SET UP PASSPORT === //
app.use( passport.initialize( ) );

// === CREATE ROUTER === //
var router  =  express.Router( );

// === CUSTOM FUNCTION TO GENERATE RETURN MESSAGE FOR BAD ROUTES === //
function getBadRouteJSON( req , res , route )
{
	res.json(	{	
					success:  false, 
					msg:      req.method + " requests are not supported by " + route
				});
}

// === CUSTOM FUNCTION TO RETURN JSON OBJECT OF HEADER, KEY, AND BODY OF REQUEST === //
function getJSONObject( req ) 
{
    var json = {
					headers  :  "No Headers",
					key      :  process.env.UNIQUE_KEY,
					body     :  "No Body"
				};

    if ( req.body != null ) 
        json.body  =  req.body;
	
    if ( req.headers != null ) 
        json.headers  =  req.headers;

    return json;
}

// === CUSTOM FUNCTION TO RETURN JSON OBJECT OF STATUS, MESSAGE, HEADER, QUERY, & ENVIRONMENT KEY FOR /MOVIES === //
function getMoviesJSONObject( req , msg )
{
	var json = {
					status   :  200,
					message  :  msg,
					headers  :  "No Headers",
					query    :  "No Query String",
					env      :  process.env.UNIQUE_KEY
				};
	
	if ( req.query != null )
		json.query  =  req.query; 

	if ( req.headers != null )
		json.headers  =  req.headers;
	
	return json;
}



// === ROUTES TO /POST PERFORM A "SMART ECHO" WITH BASIC AUTH === //
router.route('/post')
    .post(
		authController.isAuthenticated, 
		function ( req , res ) 
		{
            console.log( req.body );
            res  =  res.status( 200 );
            if ( req.get( 'Content-Type' ) ) 
			{
                console.log( "Content-Type: " + req.get( 'Content-Type' ) );
                res  =  res.type( req.get( 'Content-Type' ) );
            }
            var o  =  getJSONObject( req );
            res.json( o );
        });

		
		
// === ROUTES TO /POSTJWT PERFORM AN "ECHO" WITH JWT AUTH === //
router.route( '/postjwt' )
    .post(
		authJwtController.isAuthenticated, 
		function ( req , res )
		{
            console.log( req.body );
            res  =  res.status( 200 );
            if ( req.get( 'Content-Type' ) ) 
			{
                console.log( "Content-Type: " + req.get( 'Content-Type' ) );
                res  =  res.type( req.get( 'Content-Type' ) );
            }
            res.send( req.body );
        }
    );

	
	
// === ROUTES TO /SIGNUP === //
router.route( '/signup' )
	// === HANDLE POST REQUESTS === //
	.post(
		function( req , res ) 
		{
			// === IF USERNAME OR PASSWORD IS INVALID: FAIL === //
			if ( !req.body.username || !req.body.password ) 
			{
				res.json({	
							success  :  false, 
							msg      :  'Please pass username and password.'
						});
			} 
			// === SAVE THE NEW USER === //
			else 
			{
				var newUser  =  {
									username  :  req.body.username,
									password  :  req.body.password
								};
				// save the user
				db.save( newUser );   //no duplicate checking
				res.json({
							success  :  true, 
							msg      :  'Successful created new user.'
						});
			}
		})
	// === ALL OTHER ROUTES TO /SIGNUP ARE REJECTED === //
	.all(
		function( req , res )
		{ 
			getBadRouteJSON( req , res , "/signup" ); 
		});

		
		
// === ROUTES TO /SIGNIN === //
router.route( '/signin' )
	// == HANDLE POST REQUESTS === //
	.post(
		function( req , res ) 
		{
			// === RETRIEVE USER === //
			var user;
			if ( req.body.username )
				user  =  db.findOne( req.body.username );
			else
				user  =  null;

			// === FAIL IF NO USER FOUND === //
			if ( !user )
				res.status( 401 ).send(	{
											success  :  false, 
											msg      :  'Authentication failed. User not found.'
										});
			// === VALIDATE PASSWORD IF USER FOUND === //
			else 
			{
				if ( req.body.password == user.password )  
				{
					var userToken  =  	{ 
											id        :  user.id, 
											username  :  user.username 
										};
					var token      =    jwt.sign( userToken , process.env.SECRET_KEY );
					res.json({ 
								success  :  true, 
								token    :  'JWT ' + token
							});
				}
				else 
				{
					res.status( 401 ).send( {
												success  :  false, 
												msg      :  'Authentication failed. Wrong password.'
											} );
				}
			}
		})
	// === ALL OTHER ROUTES TO /SIGNIN  ARE REJECTED
	.all(
		function( req , res )
		{ 
			getBadRouteJSON( req , res , "/signin" ); 
		});

// === ROUTES TO /MOVIES === //
router.route( '/movies' )
	// === HANDLE GET REQUESTS === //
	.get(
		function( req ,res )
		{
			res.json( getMoviesJSONObject( req , "GET movies" ) );
		})
	// === HANDLE POST REQUESTS === //
	.post(
		function( req , res )
		{
			res.json( getMoviesJSONObject( req , "movie saved" ) ); 
		})
	// === HANDLE PUT REQUESTS === //
	.put(
		authJwtController.isAuthenticated, 
		function( req , res )
		{
			res.json( getMoviesJSONObject( req , "movie updated" ) ); 
		})
	// === HANDLE DELETE REQUESTS === //
	.delete(
		authController.isAuthenticated, 
		function( req , res )
		{
			res.json( getMoviesJSONObject( req , "movie deleted" ) );
		})
	// === REJECT ALL OTHER REQUESTS TO /MOVIES === //
	.all(
		function( req , res )
		{ 
			getBadRouteJSON( req , res , "/movies" );
		});

// === ATTEMPT TO ROUTE REQUEST === //
app.use( '/' , router );

// === IF UNEXPEDTED ROUTE IS SENT, REJECT IT HERE === //
app.use(
	function( req , res )
	{ 
		getBadRouteJSON( req , res , "this URL path" ); 
	});

// === LISTEN ON THE ENVIRONMENT PORT OR 8080 === //
app.listen( process.env.PORT || 8080 );

// === EXPORT APP FOR TESTS === //
module.exports  =  app; // for testing