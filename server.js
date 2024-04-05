/*const express = require('express');
const ejs = require('ejs');
const path = require('path');
const app = express();
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo')(session);

const MongoDBURI = process.env.MONGO_URI || 'mongodb://localhost/ManualAuth';

mongoose.connect(MongoDBURI, {
  useUnifiedTopology: true,
  useNewUrlParser: true
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', () => {
});

app.use(session({
  secret: 'work hard',
  resave: true,
  saveUninitialized: false,
  store: new MongoStore({
    mongooseConnection: db
  })
}));

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

app.use(express.static(__dirname + '/views'));

const index = require('./routes/index');
app.use('/', index);

// catch 404 and forward to error handler
app.use((req, res, next) => {
  const err = new Error('File Not Found');
  err.status = 404;
  next(err);
});

// error handler
// define as the last app.use callback
app.use((err, req, res, next) => {
  res.status(err.status || 500);
  res.send(err.message);
});

// listen on port 3000
app.listen(process.env.PORT || 3000, () => {
  console.log('Express app listening on port 3000');
});

const express = require('express');
const nodemailer = require('nodemailer');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const path = require('path');
const app = express();


app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');


const PORT = process.env.PORT || 3000;

// Store email addresses and their corresponding OTPs in memory (for demonstration purposes)
const otpMap = new Map();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.get('/',(req,res)=>{
res.render('form');
}
);
app.post('/send-otp', async (req, res) => {
    const email = req.body.email;
    const otp = generateOTP();

    try {
        await sendOTP(email, otp);
        otpMap.set(email, otp); // Store OTP in memory for the given email address
        res.send('OTP sent successfully!');
    } catch (error) {
        console.error('Failed to send OTP:', error);
        res.status(500).send('Failed to send OTP. Please try again later.');
    }
});

app.post('/verify-otp', (req, res) => {
    const email = req.body.email;
    const enteredOTP = req.body.otp;

    if (!otpMap.has(email)) {
        res.status(400).send('No OTP found for the provided email address.');
        return;
    }

    const storedOTP = otpMap.get(email);

    if (enteredOTP === storedOTP) {
        res.send('OTP verification successful!');
        // Optionally, you can remove the OTP from memory after successful verification
        otpMap.delete(email);
    } else {
        res.status(400).send('Invalid OTP. Please try again.');
    }
});

function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000);
}

async function sendOTP(email, otp) {
    let transporter = nodemailer.createTransport({
        service: 'Gmail',
        auth: {
            user: 'jayeshj221990@gmail.com', // Enter your email address
            pass: 'Jayesh@21911203' // Enter your email password
        }
    });

    let mailOptions = {
        from: 'hygosavi9834@gmail.com', // Enter your email address
        to: email,
        subject: 'OTP Verification',
        text: `Your OTP is: ${otp}.`
    };

    await transporter.sendMail(mailOptions);
}

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
*/





const express = require('express');
const mysql = require('mysql');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const ejs = require('ejs');
const path = require('path');
const app = express();


app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(cookieParser());
app.use(bodyParser.json());
app.use(express.json());



const PORT = process.env.PORT || 3000;

const secretKey = '1234'; // Change this to a random secret key

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root', // Enter your MySQL username
  password: 'root', // Enter your MySQL password
  database: 'restapi' // Enter your database name
});

connection.connect((err) => {
  if (err) throw err;
  console.log('Connected to MySQL database');
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

app.get('/',(req,res)=>{
	const token = req.cookies.token;
	if(token)
		res.render('otp.ejs',{message:''});
	else
	    res.render('signup',{message:''});
});
app.get('/login',(req,res)=>{
		const token = req.cookies.token;

	if(token)
	{
		const page = req.query.page || 1; // Default to page 1 if not specified
			const pageSize = 5; // Number of categories per page
			const startIndex = (page - 1) * pageSize; // Calculate the start index
			const data = [];

			connection.query('SELECT * FROM categories LIMIT ?, ?', [startIndex, pageSize], (error, categories) => {
			if (error) {
            console.error('Database error:', error);
            res.status(500).json({ error: 'Database error' }); 
			} else {
				const userId = req.cookies.userId; 

            // Iterate over categories
				categories.forEach(category => {
					const categoryId = category.id;

                // Execute query to check if the user has this category
					connection.query('SELECT * FROM user_categories WHERE userId = ? AND categoryId = ?', [userId, categoryId], (err, results) => {
                    if (err) {
                        console.error('Database error:', err);
                    } else {
                        results.forEach(result => {
                            const isActive = result.isActive === 1 ? 1 : 0;
                            data.push({ category, isActive });
                        });
						console.log(data);
                        if (results.length === 0) {
                            data.push({ category, isActive: 0 });
                        }

                        if (data.length === categories.length) {
                            console.log('Data:', data);

                            res.render('categories', { data });
                        }
                    }
                });
            });
        }
    });
	}
    else
		res.render('login.ejs',{message:''});
});

app.post('/verifyOTP',(req,res)=>{
	
	const submittedOTP  = req.body.join('');;
	console.log(submittedOTP);
    const correctOTP = '12345678'; // Correct OTP for demonstration, replace it with your logic
    
    if (submittedOTP === correctOTP) {
        res.json("success");
		//res.render('login.ejs', {message: ''});
    } else {
		console.log("invalid OTP")
        res.json("Invalid OTP.Please try again");
    }
});


// Signup route
app.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  
  // Check if the email already exists
  connection.query('SELECT * FROM users WHERE email = ?', [email], (error, results) => {
    if (error) {
      console.error('Database error:', error);
      res.status(500).send('Database error. Please try again later.');
    } else {
      if (results.length > 0) {
        // Email already exists
        res.render('signup', { message: 'Email already exists. Please use a different email.' });
      } else {
        // Email does not exist, proceed with registration
        const user = { name, email, password: hashedPassword };
        connection.query('INSERT INTO users SET ?', user, (error, results) => {
          if (error) {
            console.error('Failed to register user:', error);
            res.status(500).send('Failed to register user. Please try again later.');
          } else {
            console.log('User registered successfully');
            const token = jwt.sign({ username: req.body.name }, secretKey, { expiresIn: '30d' });
            res.cookie('token', token,  { maxAge: 30 * 24 * 60 * 60 * 1000 }); // 30 days expiry

            res.render('otp', { message: user.email });
          }
        });
      }
    }
  });
});

// Login route
app.post('/categories', (req, res) => {
  const { email, password } = req.body;
  connection.query('SELECT * FROM users WHERE email = ?', [email], async (error, results) => {
    if (error) {
      console.error('Database error:', error);
      res.status(500).send('Database error. Please try again later.');
    } else {
      if (results.length > 0) {
        const match = await bcrypt.compare(password, results[0].password);
        if (match) {

			const userId = results[0].id;
			const token = jwt.sign({ email: email }, secretKey, { expiresIn: '30d' }); // 30 days expiry
			res.cookie('token', token, { maxAge: 30 * 24 * 60 * 60 * 1000 });
			res.cookie('userId', userId,  { maxAge: 30 * 24 * 60 * 60 * 1000 }); // 30 days expiry
			const page = req.query.page || 1; // Default to page 1 if not specified
			const pageSize = 5; // Number of categories per page
			const startIndex = (page - 1) * pageSize; // Calculate the start index
			const data = [];

			connection.query('SELECT * FROM categories LIMIT ?, ?', [startIndex, pageSize], (error, categories) => {
			if (error) {
            console.error('Database error:', error);
            res.status(500).json({ error: 'Database error' }); 
			} else {
				const userId = req.cookies.userId; 

            // Iterate over categories
				categories.forEach(category => {
					const categoryId = category.id;

                // Execute query to check if the user has this category
					connection.query('SELECT * FROM user_categories WHERE userId = ? AND categoryId = ?', [userId, categoryId], (err, results) => {
                    if (err) {
                        console.error('Database error:', err);
                    } else {
                        results.forEach(result => {
                            const isActive = result.isActive === 1 ? 1 : 0;
                            data.push({ category, isActive });
                        });
						console.log(data);
                        if (results.length === 0) {
                            data.push({ category, isActive: 0 });
                        }

                        if (data.length === categories.length) {
                            console.log('Data:', data);

                            res.render('categories', { data });
                        }
                    }
                });
            });
        }
    });
        } else {
          res.render('login', { message: 'Incorrect email or password' });
        }
      } else {
        res.render('login', { message: 'Incorrect email or password' });
      }
    }
  });
});
// Dashboard route (protected)
app.get('/dashboard', authenticateToken, (req, res) => {
  res.json(req.user);
});


app.get('/categories', (req, res) => {
    const page = req.query.page || 1; // Default to page 1 if not specified
    const pageSize = 5; // Number of categories per page
    const startIndex = (page - 1) * pageSize; // Calculate the start index
    const data = [];

    connection.query('SELECT * FROM categories LIMIT ?, ?', [startIndex, pageSize], (error, categories) => {
        if (error) {
            console.error('Database error:', error);
            res.status(500).json({ error: 'Database error' }); 
        } else {
            const userId = req.cookies.userId; 

            // Iterate over categories
            categories.forEach(category => {
                const categoryId = category.id;

                // Execute query to check if the user has this category
                connection.query('SELECT * FROM user_categories WHERE userId = ? AND categoryId = ?', [userId, categoryId], (err, results) => {
                    if (err) {
                        console.error('Database error:', err);
                        // Handle error if necessary
                    } else {
                        // Check if result is active or not
                        results.forEach(result => {
                            const isActive = result.isActive === 1 ? 1 : 0;
                            data.push({ category, isActive });
                        });
						console.log(data);
                        if (results.length === 0) {
                            data.push({ category, isActive: 0 });
                        }

                        // Check if all categories have been processed
                        if (data.length === categories.length) {
                            console.log('Data:', data);

                            // Render categories page with data
                            res.render('categories', { data });
                        }
                    }
                });
            });
        }
    });
});


app.put('/save', (req, res) => {
	
  const userID = req.cookies.userId;
  const categories = req.body;//list of categoriesId
console.log(categories[0]);

  // Loop through each category received in the request
  categories.forEach(category => {
    const categoryId = category.categoryId;
    const isActive = category.status;

    // Check if the user already has an entry for this category
    connection.query('SELECT * FROM user_categories WHERE userId = ? AND categoryId = ?', [userID, categoryId], (error, results) => {
      if (error) {
        console.error('Database error:', error);
        res.status(500).json({ error: 'Database error' });
      } else {
		  
        	const row = results.length;
				
				if(row){
          // User category entry already exists, update it
          connection.query('UPDATE user_categories SET isActive = ? WHERE userId = ? AND categoryId = ?', [isActive, userID, categoryId], (updateError, updateResults) => {
            if (updateError) {
              console.error('Update error:', updateError);
              res.status(500).json({ error: 'Update error' });
            }
			});
		   }
        else { 
			
			if(isActive) {
          // User category entry doesn't exist, insert a new one
			connection.query('INSERT INTO user_categories (userId, categoryId, isActive) VALUES (?, ?, ?)', [userID, categoryId, isActive], (insertError, insertResults) => {
            if (insertError) {
              console.error('Insert error:', insertError);
              res.status(500).json({ error: 'Insert error' });
				}
				});
			}
			
			}
		  
        }
      
    });
  });

  // Respond with success once all categories are processed
  res.status(200).json({ message: 'Categories saved successfully' });
});

/*
// Update user-selected categories
app.put('/categories', (req, res) => {
	const userID = req.cookies.userId;
  const categories = req.body.data;//list of categoriesId
  
  
  for(var category of categories)
  {const result = connection.query('	select * from user_categories where userID = ? and categoryId = ?
	if(result.length > 0)
	{
		if(category[1]==0)
		update from user_categories set isActive to 0
		else
			set to 1
		
	}
	else
	{
		insert into user_categories user_id ,categoty[0],isactive true
	}
  }
  connection.query('DELETE FROM user_categories WHERE user_id = ?', [userId], (error, results) => {
    if (error) throw error;
    // Insert new user categories
    const userCategoryValues = categories.map(categoryId => [userId, categoryId]);
    connection.query('INSERT INTO user_categories (user_id, category_id) VALUES ?', [userCategoryValues], (error, results) => {
      if (error) throw error;
      res.send('User categories updated successfully');
    });
  });
});
*/
function authenticateToken(req, res, next) {
  c/*onst authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.status(401).send('Unauthorized');

  jwt.verify(token, secretKey, (err, user) => {
    if (err) return res.status(403).send('Forbidden');
    req.user = user;
    next();
  });
  */
  
  const token = req.cookies.token
  const auth = req.headers.authorization;
//console.log(auth)
  if (!token) return res.status(401).json({ message: 'Access denied' });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });

    req.user = user;
    next();
  });
}

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
