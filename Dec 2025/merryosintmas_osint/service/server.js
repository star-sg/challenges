const express = require('express');
const path = require('path');
const app = express();

// const cors = require("cors");
// const corsOptions = {
//     origin: ["http://localhost:5173"]
// };
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const RELEASE_DATE = new Date('2025-12-09T00:00:00+08:00'); //UTC date for second chall release

const PORT = process.env.PORT || 1337;
const BUILD_PATH = path.join(__dirname, 'src');
const FILENAME = './challs.json';
const jsonObject = JSON.parse(fs.readFileSync(FILENAME, 'utf8'));

// app.use(cors(corsOptions));
app.use(express.json());
app.use(express.static(BUILD_PATH));
app.set('trust proxy', 1); //configured for 1 layer of proxy

const apiLimiter = rateLimit({
    windowMs: 60 * 1000, 
    max: 5, // Limit each IP to 5 requests per min
    standardHeaders: true, 
    legacyHeaders: false,
    message: async (req, res) => {
        return res.status(429).send({ 
            message: 'Too many requests. Please try again later.' 
        });
    }
});


app.post('/api/submit', apiLimiter, (req,res)=>{
    const {id, guess} = req.body; // reject any that dont split
    // console.log(id)

    if (!id || !guess) {
        return res.status(400).send('Missing ID or guess in request body');
    }
    const sanitizedId = id.toString().replace(/[^0-9]/g, ''); // only digits
    const sanitizedGuess = guess.toString().replace(/[^0-9a-fA-F]/g, ''); // only hex characters

    if (!sanitizedId || !sanitizedGuess) {
        return res.status(400).send('Missing ID or guess in request body');
    }
    
    if (sanitizedGuess===jsonObject[sanitizedId]["hash"]){
        res.status(200).send(jsonObject[sanitizedId]["share"]);
    }
    else {
        res.status(200).send("");
    }
    
})

app.get('/winter-1derland', (req, res) => {
    // time gate the release
    const now = new Date();
    if (now<RELEASE_DATE){
        return res.status(404).send("");
    }
    res.sendFile(path.join(BUILD_PATH, 'index.html'));
});

app.get('/*path', (req, res) => {
    // If the path isn't a file or an API endpoint, send the main HTML page.
    res.sendFile(path.join(BUILD_PATH, 'index.html'));
});



app.listen(PORT, () => {
    console.log(`Server started on port ${PORT}`);
});
