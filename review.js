// === GRAB EXTERNAL RESOURCES === //
var mongoose  =  require( 'mongoose' );
var Schema    =  mongoose.Schema;

// === CREATE THE USER SCHEMA === //
var reviewSchema  =  new Schema({
		movieTitle :	{ 
							type     : String, 
							required : true
						},
		reviewer   :	{ 
							type     : String, 
							required : true 
						},
		quote      :	{
							type     : String,
							required : true
						},
		rating     :	{
							type     : float,
							required : true
						}
	});
	
// === CREATE THE USER MODEL === //
var Review  =  mongoose.model( 'Review' , reviewSchema );

// === EXPORT THE USER MODEL === //
module.exports  =  Review;