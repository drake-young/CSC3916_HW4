/**
 * Created by shawnmccarthy on 1/22/17.
 */
'use strict;';

// === INCLUDE CRYPTO TO GENERATE THE MOVIE ID === //
var crypto  =  require( 'crypto' );

// === EXPORT THE DATABASE FUNCTIONS === //
module.exports = function () {
    return {
        userList:	[],
        /*
         * Save the user inside the "db".
         */
        save:		function ( user ) 
					{
						user.id  =  crypto.randomBytes( 20 ).toString( 'hex' ); // fast enough for our purpose
						this.userList.push( user );
						return 1;
					},
        /*
         * Retrieve a movie with a given id or return all the movies if the id is undefined.
         */
        find: 		function ( id ) 
					{
						// === IF AN ID IS PROVIDED, FIND USER WITH THAT ID === //
						if ( id ) 
						{
							return this.userList.find(	function ( element ) 
														{
															return element.id === id;
														});
						}
						// === IF NO ID IS PROVIDED, RETURN THE WHOLE USER LIST === //
						else 
						{
							return this.userList;
						}
					},
        findOne: 	function ( name ) 
					{
						// === IF NAME IS PROVIDED, SEARCH DATABASE FOR THAT USER === //
						if ( name ) 
						{
							return this.userList.find(	function ( element ) 
														{
															return element.username === name;
														});
						}
						else 
						{
							return this.userList;
						}
					},
        /*
         * Delete a movie with the given id.
         */
        remove: 	function ( id ) 
					{
						var found      =  0;
						this.userList  =  this.userList.filter(	function ( element ) 
																{
																	if ( element.id === id ) 
																	{
																		found  =  1;
																	}
																	else 
																	{
																		return element.id !== id;
																	}
																});
						return found;
					},
        /*
         * Update a movie with the given id
         */
        update: 	function ( id , user ) 
					{
						// === RETRIEVE USER TO UPDATE === //
						var userIndex  =  this.userList.findIndex(	function ( element )
																	{
																		return element.id === id;
																	});
																	
						// === IF USER IS FOUND IN DATABASE, UPDATE ITS VALUES === //
						if ( userIndex !== -1 ) 
						{
							this.userList[ userIndex ].username  =  user.username;
							this.userList[ userIndex ].password  =  user.password;
							return 1;
						}
						// === OTHERWISE RETURN === //
						else 
						{
							return 0;
						}
					}
    };
};