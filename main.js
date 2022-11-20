var secrets = require("./secrets.js");

var express = require('express');
var app = express();
var fs = require('fs');
var mysql = require('mysql');
var md5 = require('md5');

var http = require('http').createServer(function (req, res) {
	res.writeHead(301, { "Location": "https://" + req.headers['host'] + req.url });
	res.end();
});

// var http = require('http').createServer(app);

const privateKey = fs.readFileSync('/etc/letsencrypt/live/hscsa.org/privkey.pem', 'utf8');
const certificate = fs.readFileSync('/etc/letsencrypt/live/hscsa.org/cert.pem', 'utf8');
const ca = fs.readFileSync('/etc/letsencrypt/live/hscsa.org/chain.pem', 'utf8');

const credentials = {
	key: privateKey,
	cert: certificate,
	ca: ca
};

var https = require('https').createServer(credentials,app);
var io = require('socket.io')(https);

var db_config = {
	host: "localhost",
	user: "root",
	password: secrets.password,
	database: "hscsa",
	multipleStatements: true
};

var con;

function handleDisconnect() {
	con = mysql.createConnection(db_config);
	con.connect(function(err) {
	if(err) {
		console.log('error when connecting to db:',err);
		setTimeout(handleDisconnect,2000);
		}
	});
	con.on('error',function(err) {
		console.log('db error',err);
		if(err.code === 'PROTOCOL_CONNECTION_LOST') {
			handleDisconnect();
		}else{
			throw err;
		}
	});
}

handleDisconnect();

io.on('connection',(socket) => {
	socket.on('register',(tn,pwd) => {
		con.query("SELECT * FROM users WHERE name=?;",[tn],function(err,result,fields) {
			if(err) {
				console.log("Something went very wrong with " + tn);
				console.log(err);
				socket.emit("regRes",false,-2);
				return;
			}
			if(result.length > 0) {
				socket.emit("regRes",false,-1);
				return;
			}
			var uid = makeID(12);

			con.query("INSERT INTO users (name,password,uid,permission,display) VALUES (?,?,?,?,?);",[
					tn,md5(pwd),uid,0,tn
				],function(err,result,fields) {
				if(err) {
					console.log("Something went very wrong with " + tn);
					console.log(err);
					socket.emit("regRes",false,-2);
					return;
				}
				socket.emit("regRes",true,uid);
				console.log("User " + tn + " is registered!");				
			});
			
		});
	});

	socket.on('reqProfile',(id) => {
		con.query("SELECT * FROM users WHERE uid=?;",[id],function(err,result,fields) {
			if(err) {
				console.log("Something went wrong while someone asked for id " + id);
				return;
			}
			socket.emit("profileRes",result[0]);
		});
	});

	socket.on('saveChanges',(id,inp) => {
		con.query("UPDATE users SET display=?,organization=?,members=?,email=? WHERE uid=?",[
			inp["display"],inp["organization"],inp["members"],inp["email"],id],
			function(err,result,fields) {
			if(err) {
				console.log("Something went wrong while someone asked for id " + id);
				socket.emit("saveChangesRes",-1);
				return;
			}
			socket.emit("saveChangesRes",1);
			return;
		});
	});

	socket.on('postProposal',(id,prop) => {
		con.query("SELECT * FROM users WHERE uid=?;",[id],function(err,result,fields) {
			if(err) {
				console.log("Something went wrong while someone asked for id " + id);
				return;
			}
			if(result.length == 0) return;
			if(result["permission"] & 3 == 0) {
				// Not enough permission
				socket.emit("postProposalRes",-1);
				return;
			}
			var author = result[0]["name"];
			prop["difficulty"] = Math.max(1,Math.min(10,prop["difficulty"]));
			con.query("INSERT INTO proposals (pname,author,difficulty,categories,statement,solution) VALUES (?,?,?,?,?,?);",
				[prop["pname"],author,prop["difficulty"],prop["categories"],prop["statement"],prop["solution"]],function(err,result,fields) {
					if(err) {
						console.log("Something went wrong while someone asked for id " + id);
						console.log(err);
						return;
					}
					socket.emit("postProposalRes",1);
				});
		});
	});

	socket.on('getProposals',(id,prop) => {
		con.query("SELECT * FROM users WHERE uid=?;",[id],function(err,result,fields) {
			if(err) {
				console.log("Something went wrong while someone asked for id " + id);
				return;
			}
			if(result.length == 0) return;
			if((result[0]["permission"] & 3) == 0) {
				// Not enough permission
				socket.emit("getProposalRes",-1);
				return;
			}
			con.query("SELECT * FROM proposals;",function(err,res,fields) {
					if(err) {
						console.log("Something went wrong while someone asked for id " + id);
						return;
					}
					socket.emit("getProposalsRes",res);
				});
		});
	});

	socket.on('deleteProposal',(id,pid) => {
		con.query("SELECT * FROM users WHERE uid=?;",[id],function(err,result,fields) {
			if(err) {
				console.log("Something went wrong while someone asked for id " + id);
				return;
			}
			if(result.length == 0) return;
			if((result[0]["permission"] & 3) == 0) {
				// Not enough permission
				socket.emit("getProposalRes",-1);
				return;
			}
			con.query("DELETE FROM proposals WHERE id=?;",[pid],function(err,res,fields) {
					if(err) {
						console.log("Something went wrong while someone asked for id " + id);
						socket.emit("deleteProposalRes",-1);
						return;
					}
					socket.emit("deleteProposalRes",1);
				});
		});
	});

	socket.on('login',(tn,pwd) => {
		con.query("SELECT * FROM users WHERE name=?;",[tn],function(err,result,fields) {
			if(err) {
				console.log("Something went very wrong with " + tn);
				console.log(err);
				socket.emit("loginRes",false,-2);
				return;
			}
			if(result.length == 0) {
				socket.emit("loginRes",false,-1);
				return;
			}
			if(result[0]["password"] != md5(pwd)) {
				socket.emit("loginRes",false,-3);
				return;
			}
			socket.emit("loginRes",true,result[0]["uid"]);
			return;
		});

	});
});

function makeID(length) {
    var result           = '';
    var characters       = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    var charactersLength = characters.length;
    for ( var i = 0; i < length; i++ ) {
      result += characters.charAt(Math.floor(Math.random() * charactersLength));
   }
   return result;
}

app.use("/", express.static(__dirname + '/static'));
app.get('/',(req,res) => {res.sendFile(__dirname + '/index.html');});
app.get('/monthly',(req,res) => {res.sendFile(__dirname + '/monthly/monthly.html');});
app.get('/login',(req,res) => {res.sendFile(__dirname + '/monthly/login.html');});
app.get('/register',(req,res) => {res.sendFile(__dirname + '/monthly/register.html');});
app.get('/profile',(req,res) => {res.sendFile(__dirname + '/monthly/profile.html');});
app.get('/results',(req,res) => {res.sendFile(__dirname + '/monthly/results.html');});
app.get('/proposal',(req,res) => {res.sendFile(__dirname + '/monthly/proposal.html');});

http.listen(8002,() => {
	console.log('listening on *:8002');
});
https.listen(4432,() => {
 	console.log('listening on *:4432');
});