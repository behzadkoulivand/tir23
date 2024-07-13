'use strict';

/*
███████ ███████ ██████  ██    ██ ███████ ██████  
██      ██      ██   ██ ██    ██ ██      ██   ██ 
███████ █████   ██████  ██    ██ █████   ██████  
     ██ ██      ██   ██  ██  ██  ██      ██   ██ 
███████ ███████ ██   ██   ████   ███████ ██   ██                                           

dependencies: {
    @sentry/node            : https://www.npmjs.com/package/@sentry/node
    @sentry/integrations    : https://www.npmjs.com/package/@sentry/integrations
    axios                   : https://www.npmjs.com/package/axios
    body-parser             : https://www.npmjs.com/package/body-parser
    compression             : https://www.npmjs.com/package/compression
    colors                  : https://www.npmjs.com/package/colors
    cors                    : https://www.npmjs.com/package/cors
    crypto-js               : https://www.npmjs.com/package/crypto-js
    express                 : https://www.npmjs.com/package/express
    httpolyglot             : https://www.npmjs.com/package/httpolyglot
    jsonwebtoken            : https://www.npmjs.com/package/jsonwebtoken
    mediasoup               : https://www.npmjs.com/package/mediasoup
    mediasoup-client        : https://www.npmjs.com/package/mediasoup-client
    ngrok                   : https://www.npmjs.com/package/ngrok
    openai                  : https://www.npmjs.com/package/openai
    qs                      : https://www.npmjs.com/package/qs
    socket.io               : https://www.npmjs.com/package/socket.io
    swagger-ui-express      : https://www.npmjs.com/package/swagger-ui-express
    uuid                    : https://www.npmjs.com/package/uuid
    xss                     : https://www.npmjs.com/package/xss
    yamljs                  : https://www.npmjs.com/package/yamljs
}
*/

/**
 * MiroTalk SFU - Server component
 *
 * @link    GitHub: https://github.com/miroslavpejic85/mirotalksfu
 * @link    Official Live demo: https://sfu.mirotalk.com
 * @license For open source use: AGPLv3
 * @license For commercial or closed source, contact us at license.mirotalk@gmail.com or purchase directly via CodeCanyon
 * @license CodeCanyon: https://codecanyon.net/item/mirotalk-sfu-webrtc-realtime-video-conferences/40769970
 * @author  Miroslav Pejic - miroslav.pejic.85@gmail.com
 * @version 1.3.87
 *
 */

const express = require('express');
const cors = require('cors');
const compression = require('compression');
const https = require('httpolyglot');
const mediasoup = require('mediasoup');
const mediasoupClient = require('mediasoup-client');
const http = require('http');
const path = require('path');
const axios = require('axios');
const ngrok = require('ngrok');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const config = require('./config.js');
const checkXSS = require('./XSS.js');
const Host = require('./Host');
const Room = require('./Room');
const Peer = require('./Peer');
const ServerApi = require('./ServerApi');
const Logger = require('./Logger');
const log = new Logger('Server');
const yamlJS = require('yamljs');
const swaggerUi = require('swagger-ui-express');
const swaggerDocument = yamlJS.load(path.join(__dirname + '/../api/swagger.yaml'));
const Sentry = require('@sentry/node');
const { CaptureConsole } = require('@sentry/integrations');
const restrictAccessByIP = require('./middleware/IpWhitelist.js');
const packageJson = require('../../package.json');
const connectDB = require('./users/db.js');
const bcrypt = require('bcryptjs');
const User = require('./users/User.js');
const Didar = require('./users/didar.js');
const {formatDate, formatDate2} = require('./jalali.js');
const {convertDigitsFAtoEN} = require('./convertDigit.js');
const Chart = require('./users/Chart.js');
const SecDidar = require('./users/Secure.js');
const { authenticated, authenticated2 } = require('./middleware/auth.js');
const { errorHandler } = require('./middleware/errors.js');

// Slack API
const CryptoJS = require('crypto-js');
const qS = require('qs');
const slackEnabled = config.slack.enabled;
const slackSigningSecret = config.slack.signingSecret;
const bodyParser = require('body-parser');

connectDB();

const app = express();

const options = {
    cert: fs.readFileSync(path.join(__dirname, config.server.ssl.cert), 'utf-8'),
    key: fs.readFileSync(path.join(__dirname, config.server.ssl.key), 'utf-8'),
};

const corsOptions = {
    origin: config.server?.origin || '*',
    methods: config.server?.cors?.methods || ['GET', 'POST'],
};

const httpsServer = https.createServer(options, app);
const io = require('socket.io')(httpsServer, {
    maxHttpBufferSize: 1e7,
    transports: ['websocket'],
    cors: corsOptions,
});

const host = 'http://' + 'localhost' + ':' + config.server.listen.port; // config.server.listen.ip

const jwtCfg = {
    JWT_KEY: (config.jwt && config.jwt.key) || 'mirotalksfu_jwt_secret',
    JWT_EXP: (config.jwt && config.jwt.exp) || '1h',
};

const hostCfg = {
    protected: config.host.protected,
    user_auth: config.host.user_auth,
    users_from_db: config.host.users_from_db,
    users_api_endpoint: config.host.users_api_endpoint,
    users_api_secret_key: config.host.users_api_secret_key,
    users: config.host.users,
    authenticated: false,
    admin: false,
    supervisor: false,
    security: false
};

const restApi = {
    basePath: '/api/v1', // api endpoint path
    docs: host + '/api/v1/docs', // api docs
    allowed: config.api?.allowed,
};

// Sentry monitoring
const sentryEnabled = config.sentry.enabled;
const sentryDSN = config.sentry.DSN;
const sentryTracesSampleRate = config.sentry.tracesSampleRate;
if (sentryEnabled) {
    Sentry.init({
        dsn: sentryDSN,
        integrations: [
            new CaptureConsole({
                // ['log', 'info', 'warn', 'error', 'debug', 'assert']
                levels: ['error'],
            }),
        ],
        tracesSampleRate: sentryTracesSampleRate,
    });
    /*
    log.log('test-log');
    log.info('test-info');
    log.warn('test-warning');
    log.error('test-error');
    log.debug('test-debug');
    */
}

// Stats
const defaultStats = {
    enabled: true,
    src: 'https://stats.mirotalk.com/script.js',
    id: '41d26670-f275-45bb-af82-3ce91fe57756',
};

// OpenAI/ChatGPT
let chatGPT;
if (config.chatGPT.enabled) {
    if (config.chatGPT.apiKey) {
        const { OpenAI } = require('openai');
        const configuration = {
            basePath: config.chatGPT.basePath,
            apiKey: config.chatGPT.apiKey,
        };
        chatGPT = new OpenAI(configuration);
    } else {
        log.warning('ChatGPT seems enabled, but you missing the apiKey!');
    }
}

// directory
const dir = {
    public: path.join(__dirname, '../../', 'public'),
    rec: path.join(__dirname, '../', config?.server?.recording?.dir ? config.server.recording.dir + '/' : 'rec/'),
};

// rec directory create
const serverRecordingEnabled = config?.server?.recording?.enabled;
if (serverRecordingEnabled) {
    if (!fs.existsSync(dir.rec)) {
        fs.mkdirSync(dir.rec, { recursive: true });
    }
}

// html views
const views = {
    about: path.join(__dirname, '../../', 'public/views/about.html'),
    landing: path.join(__dirname, '../../', 'public/views/landing.html'),
    login: path.join(__dirname, '../../', 'public/views/login.html'),
    newRoom: path.join(__dirname, '../../', 'public/views/newroom.html'),
    notFound: path.join(__dirname, '../../', 'public/views/404.html'),
    permission: path.join(__dirname, '../../', 'public/views/permission.html'),
    privacy: path.join(__dirname, '../../', 'public/views/privacy.html'),
    room: path.join(__dirname, '../../', 'public/views/Room.html'),
    register: path.join(__dirname, '../../', 'public/views/register.html'),
    dashboard: path.join(__dirname, '../../', 'public/views/dashboard.ejs'),
    addDidar: path.join(__dirname, '../../', 'public/views/addDidar.html'),
    chart: path.join(__dirname, '../../', 'public/views/chart.html'),
    addChart: path.join(__dirname, '../../', 'public/views/addChart.html'),
    changePassword: path.join(__dirname, '../../', 'public/views/changePassword.html')
};

const authHost = new Host(); // Authenticated IP by Login

const roomList = new Map(); // All Rooms

const presenters = {}; // collect presenters grp by roomId

let announcedAddress = config.mediasoup.webRtcTransport.listenInfos[0].announcedAddress; // announcedAddress (server public IPv4)

// All mediasoup workers
let workers = [];
let nextMediasoupWorkerIdx = 0;

// Autodetect announcedAddress (https://www.ipify.org)
if (!announcedAddress) {
    http.get(
        {
            host: 'api.ipify.org',
            port: 80,
            path: '/',
        },
        (resp) => {
            resp.on('data', (ip) => {
                announcedAddress = ip.toString();
                config.mediasoup.webRtcTransport.listenInfos.forEach((info) => {
                    info.announcedAddress = announcedAddress;
                });
                startServer();
            });
        },
    );
} else {
    startServer();
}

function startServer() {
    // Start the app
    app.use(cors(corsOptions));
    app.use(compression());
    app.use(express.json());
    app.use(express.static(dir.public));
    app.use(bodyParser.urlencoded({ extended: true }));
    app.use(restApi.basePath + '/docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument)); // api docs

    // IP Whitelist check ...
    app.use(restrictAccessByIP);

    // Logs requests
    app.use((req, res, next) => {
        log.debug('New request:', {
            // headers: req.headers,
            body: req.body,
            method: req.method,
            path: req.originalUrl,
        });
        next();
    });

    // POST start from here...
    app.post('*', function (next) {
        next();
    });

    // GET start from here...
    app.get('*', function (next) {
        next();
    });

    // Remove trailing slashes in url handle bad requests
    app.use((err, req, res, next) => {
        if (err instanceof SyntaxError || err.status === 400 || 'body' in err) {
            log.error('Request Error', {
                header: req.headers,
                body: req.body,
                error: err.message,
            });
            return res.status(400).send({ status: 404, message: err.message }); // Bad request
        }
        if (req.path.substr(-1) === '/' && req.path.length > 1) {
            let query = req.url.slice(req.path.length);
            res.redirect(301, req.path.slice(0, -1) + query);
        } else {
            next();
        }
    });

    // UI buttons configuration
    app.get('/config', (req, res) => {
        res.status(200).json({ message: config.ui ? config.ui.buttons : false });
    });

    // main page
    app.get(['/'], (req, res) => {
        if (hostCfg.protected) {
            hostCfg.authenticated = false;
            res.sendFile(views.login);
        } else {
            res.sendFile(views.landing);
        }
    });

    // set new room name and join
    app.get(['/newroom'], (req, res) => {
        if (hostCfg.protected) {
            let ip = getIP(req);
            if (allowedIP(ip)) {
                res.sendFile(views.newRoom);
            } else {
                hostCfg.authenticated = false;
                res.sendFile(views.login);
            }
        } else {
            res.sendFile(views.newRoom);
        }
    });

    // no room name specified to join || direct join
    app.get('/join/', async (req, res) => {
        if (Object.keys(req.query).length > 0) {
            log.debug('Direct Join', req.query);

            // http://localhost:3010/join?room=test&roomPassword=0&name=mirotalksfu&audio=1&video=1&screen=0&hide=0&notify=1
            // http://localhost:3010/join?room=test&roomPassword=0&name=mirotalksfu&audio=1&video=1&screen=0&hide=0&notify=0&token=token

            const { room, roomPassword, name, audio, video, screen, hide, notify, token, isPresenter } = checkXSS(
                req.query,
            );

            let peerUsername,
                peerPassword = '';
            let isPeerValid = false;
            let isPeerPresenter = false;

            if (token) {
                try {
                    const { username, password, presenter } = checkXSS(jwt.verify(token, jwtCfg.JWT_KEY));
                    peerUsername = username;
                    peerPassword = password;
                    isPeerValid = await isAuthPeer(username, password);
                    isPeerPresenter = presenter === '1' || presenter === 'true';
                } catch (err) {
                    log.error('Direct Join JWT error', { error: err.message, token: token });
                    return hostCfg.protected || hostCfg.user_auth
                        ? res.sendFile(views.login)
                        : res.sendFile(views.landing);
                }
            }

            if (hostCfg.protected && isPeerValid && isPeerPresenter && !hostCfg.authenticated) {
                const ip = getIP(req);
                hostCfg.authenticated = true;
                authHost.setAuthorizedIP(ip, true);
                log.debug('Direct Join user auth as host done', {
                    ip: ip,
                    username: peerUsername,
                    password: peerPassword,
                });
            }

            if (room && (hostCfg.authenticated || isPeerValid)) {
                return res.sendFile(views.room);
            } else {
                return res.sendFile(views.login);
            }
        }
        if (hostCfg.protected) {
            return res.sendFile(views.login);
        }
        res.redirect('/');
    });

    // join room by id
    app.get('/join/:roomId', (req, res) => {
        if (hostCfg.authenticated) {
            res.sendFile(views.room);
        } else {
            if (hostCfg.protected) {
                return res.sendFile(views.login);
            }
            res.redirect('/');
        }
        // res.sendFile(views.room);
    });

    // not specified correctly the room id
    app.get('/join/*', (req, res) => {
        res.redirect('/');
    });

    // if not allow video/audio
    app.get(['/permission'], (req, res) => {
        res.sendFile(views.permission);
    });

    // privacy policy
    app.get(['/privacy'], (req, res) => {
        res.sendFile(views.privacy);
    });

    // mirotalk about
    app.get(['/about'], (req, res) => {
        res.sendFile(views.about);
    });

    // Get stats endpoint
    app.get(['/stats'], (req, res) => {
        const stats = config.stats ? config.stats : defaultStats;
        // log.debug('Send stats', stats);
        res.send(stats);
    });

    // handle login if user_auth enabled
    app.get(['/login'], (req, res) => {
        res.sendFile(views.login);
    });

    // handle logged on host protected
    app.get(['/logged'], (req, res) => {
        const ip = getIP(req);
        if (allowedIP(ip)) {
            res.sendFile(views.landing);
        } else {
            hostCfg.authenticated = false;
            res.sendFile(views.login);
        }
    });

    app.get(['/users/register'], (req, res) => {
        if(hostCfg.authenticated && hostCfg.admin){
            res.sendFile(views.register);
        } else{
            res.sendFile(views.login);
        }
        // res.sendFile(views.register);
    });

    // app.set("view engine", "ejs");
    // app.set("views", "public/views");


    app.get(['/dashboard/:token'], authenticated, async (req, res) => {
        if(hostCfg.authenticated == true){
            let users = [];
            let allOfDidars = [];
            const didar = await Didar.find({ presenter: req.username });
            const didar2 = await Didar.find({ invited: req.username });
            if(didar2){
                for(let i = 0; i < didar2.length; i++){
                    didar.push(didar2[i]);
                }
            };
            if(req.userType == "admin") {
                users = await User.find();
            };
            if(req.userType == "security"){
                allOfDidars = await SecDidar.find();
            };

            res.render("dashboardAdmin.ejs", {
                didar,
                formatDate,
                formatDate2,
                pathh: req.userType, 
                convertDigitsFAtoEN,
                users,
                allOfDidars,
                iddd: req.userId
            });
            
        } else {
            hostCfg.authenticated = false;
            res.sendFile(views.login);
        }
        
    });
    
    // app.get(['/dashboard/admin'], async (req, res) => {
    //     if(hostCfg.authenticated == true){
    //         const didar = await Didar.find({ presenter: username_p });
    //         const didar2 = await Didar.find({ invited: username_p });
    //         if(didar2){
    //             for(let i = 0; i < didar2.length; i++){
    //                 didar.push(didar2[i]);
    //             }
    //         }
    //         // app.set("view engine", "ejs");
    //         // app.set("views", "public/views");
    //         res.render("dashboardAdmin.ejs", {
    //             didar,
    //             formatDate 
    //         });
    //     } else {
    //         hostCfg.authenticated = false;
    //         res.sendFile(views.login);
    //     } 
    // });
    // app.get(['/dashboard/supervisor'], async (req, res) => {
    //     if(hostCfg.authenticated == true){
    //         const didar = await Didar.find({ presenter: username_p });
    //         const didar2 = await Didar.find({ invited: username_p });
    //         if(didar2){
    //             for(let i = 0; i < didar2.length; i++){
    //                 didar.push(didar2[i]);
    //             }
    //         }
    //         // app.set("view engine", "ejs");
    //         // app.set("views", "public/views");
    //         res.render("dashboardSuper.ejs", {
    //             didar,
    //             formatDate 
    //         });
    //     } else {
    //         hostCfg.authenticated = false;
    //         res.sendFile(views.login);
    //     }

        
    // });
    // app.get(['/dashboard/normal'], async (req, res) => {
    //     if(hostCfg.authenticated == true){
    //         const didar = await Didar.find({ presenter: username_p });
    //         const didar2 = await Didar.find({ invited: username_p });
    //         if(didar2){
    //             for(let i = 0; i < didar2.length; i++){
    //                 didar.push(didar2[i]);
    //             }
    //         }
    //         // app.set("view engine", "ejs");
    //         // app.set("views", "public/views");
    //         res.render("dashboard.ejs", {
    //             didar,
    //             formatDate 
    //         });
    //     } else {
    //         hostCfg.authenticated = false;
    //         res.sendFile(views.login);
    //     }

        
    // });
    app.get(['/dashboard/add-didar'], async (req, res) => {
        if(hostCfg.authenticated){
            // if(hostCfg.supervisor){
            //     res.sendFile(views.addDidar);
            // } else{
            //     res.redirect("/dashboard/supervisor")
            // } 
            const userLogged = await User.findOne({username: username_p});
            const users = await User.find({organization_code: userLogged.organization_code});
            res.render("addDidar.ejs", {
                users, 
                myUsername: username_p
            });
        }
        else{
            res.sendFile(views.login);
        }

        
    });

    app.get(['/chart'], async (req, res) => {
        if(hostCfg.authenticated){
            const chartData = await Chart.find();
            if(hostCfg.admin || hostCfg.supervisor){
                // res.render("chart.ejs"), {
                //     chartData
                // }
                res.render("chart.ejs", {
                    chartData
                });
            } else{
                res.redirect("/dashboard/:token")
            } 
        }
        else{
            res.sendFile(views.login);
        }
    })

    app.get(['/dashboard/add-chart'], async (req, res) => {
        if(hostCfg.authenticated){
            if(hostCfg.admin){
               res.sendFile(views.addChart);
            } else{
                res.redirect("/dashboard/:token")
            } 
        }
        else{
            res.sendFile(views.login);
        }
    });
    app.get(['/edit-password/:id'], async (req, res) => {
        if(hostCfg.authenticated){
            res.sendFile(views.changePassword)
        } else {
            res.sendFile(views.login);
        }
    })

    // ####################################################
    // AXIOS
    // ####################################################

    // Create Didar
    app.post(['/dashboard/add-didar'], async (req, res) => {
        try {
            const { name, date, time, invited, description } = (req.body);
            await Didar.create(
                {
                    name: name,
                    invited: invited,
                    date: date,
                    time: time,
                    description: description,
                    presenter: username_p
                });
            await SecDidar.create(
                {
                    name: name,
                    invited: invited,
                    date: date,
                    time: time,
                    description: description,
                    presenter: username_p
                });
                // res.status(200).json({message: didar });
                res.redirect("/dashboard/:token");

        } catch (err) {
            console.log(err);
            res.status(400).json("error");
        }

    });

    //Create Chart
    app.post(['/dashboard/add-chart'], async (req, res) => {
        try {
            const {name, title, parent} = req.body;

            const id = Math.floor(Math.random() * 1000000);
            // const chart = await Chart.findOne({okk});
            // if(chart) {
            //     return res.status(401).json("این پایه سازمانی قبلا ثبت شده است");
            // }
            await Chart.create({
                id,
                name,
                title,
                parent
            });
            return res.status(200).json({message: "با موفقیت درست شد"});
        } catch (err) {
            console.log(err);
            return res.status(400).json({message: "مشکلی هست"});
        }
    })

    // Delete Didar
    app.get(['/delete-didar/:id'], async(req, res) => {
        try {
            // const didar = Didar.findById(req.params.id);
            // if(didar.presenter != username_p){
            //     res.status(200).json({ message: "شما فقط میتوانید جلسه‌هایی که خودتان ساخته اید حذف کنید" });
            // }
            // else{
                if(hostCfg.authenticated){
                    if(hostCfg.supervisor) {
                        await Didar.findByIdAndDelete(req.params.id);
                        res.redirect('/dashboard/:token');
                    }
                } else {
                    res.sendFile(views.login);
                }
            // }
            
        } catch (err) {
            console.log(err);
            res.status(400).json({message: "مشکلی در حذف جلسه به وجود آمده"});
        }
    });

    // Delete User
    app.get(['/delete-user/:id'], async (req, res) => {
        try {
            if(hostCfg.authenticated){
                if(hostCfg.admin) {
                    await User.findByIdAndDelete(req.params.id);
                    res.redirect("/dashboard/:token");
                }
            } else {
                res.sendFile(views.login);
            }
            
        } catch (err) {
            console.log(err);
            res.status(400).json({message: "مشکلی در حذف کاربر به وجود آمده"});
        }
        
    })

    // create user
    app.post(['/users/register'], async (req, res) => {
        try {
            //await User.userValidation(req.body);
            if(hostCfg.admin){
                const { organization_code, user_type, fullname, username, password } = req.body;
    
                const user = await User.findOne({ username });
        
                if (user)
                    return res.status(201).json({message: "کاربری با این نام کاربری موجود است"});
                    
                await User.create({ organization_code, user_type, fullname, username, password });
                return res.status(200).json({message: "عضویت با موفقیت انجام شد"});
            }
            else{
                return res.status(400).json({message:"مشکلی هست"});
            }
    

        } catch (err) {
            console.log(err);
            return res.status(400).json({message: "مشکلی پیش آمده"});
        }
    })
    // Change Password
    app.post(['/edit-password/:id'], async (req, res) => {
        const user = await User.findOne({ _id: req.params.id });

        try {
            if(hostCfg.authenticated){
                if (!user){
                    return res.redirect("/dashboard:token");
                } 
                else {
                    const { password } = checkXSS(req.body);

                    user.password = password;
                    await user.save();
                    return res.status(200).json({message: "کلمه عبور با موفقیت تغییر کرد"});
                }
            }
        } catch (err) {
            console.log(err);
            res.status(400).json({message: "مشکلی پیش آمده"});
        }
    })
    // Logout
    app.post(['/logout'], async (req, res) => {
        hostCfg.authenticated = false;
        hostCfg.admin = false;
        hostCfg.supervisor = false;
        pathh = "normal"
        // res.redirect("/");
        res.status(200).json({message: {fullname: "logout"}});

    });
    
    // handle login on host protected
    app.post(['/login'], async (req, res) => {
        //const ip = getIP(req);
        //log.debug(`Request login to host from: ${ip}`, req.body);

        const { username, password } = checkXSS(req.body);

        try {
            if (!req.body["g-recaptcha-response"]) {
                return res.status(404).json({ message: "مگه رباتی؟"})
            }
            //console.log(req.body["g-recaptcha-response"]);
            const user = await User.findOne({username});
    
            if(!user){
                return res.status(404).json({ message: "نام کاربری یا کلمه عبور اشتباه است"})
            }
                
            const isMatch = await bcrypt.compare(password, user.password);
            const fullname = user.fullname;
            const user_type = user.user_type;
            // const idd = user._id.toString();
            if(isMatch){
                const token = jwt.sign(
                    {
                        user: {
                            userId: user._id.toString(),
                            username: user.username,
                            fullname: user.fullname,
                            userType: user.user_type
                        },
                    },
                    jwtCfg.JWT_KEY
                );
                hostCfg.authenticated = true;
                // username_p = user.username;
                // iddd = user._id.toString();
                // if(user.user_type == "admin"){
                //     hostCfg.admin = true;
                //     pathh = "admin";
                // }
                // if(user.user_type == "supervisor"){
                //     hostCfg.supervisor = true;
                //     pathh = "supervisor";
                // }
                // if(user.user_type == "security"){
                //     hostCfg.security = true;
                //     pathh = "security";
                // }
                res.status(200).json({ message: {token: token, username: username, fullname: fullname} });
            } else {
                return res.status(401).json({ message: "نام کاربری یا کلمه عبور اشتباه است" });
            }
                
            
        } catch (err) {
            console.log(err);
            return res.status(500).json({message: "مشکلی از سمت سرور به وجود آمده است"})
        }

        //const isPeerValid = await isAuthPeer(username, password);

        // if (hostCfg.protected && isPeerValid && !hostCfg.authenticated) {
        //     const ip = getIP(req);
        //     hostCfg.authenticated = true;
        //     authHost.setAuthorizedIP(ip, true);
        //     log.debug('HOST LOGIN OK', {
        //         ip: ip,
        //         authorized: authHost.isAuthorizedIP(ip),
        //         authorizedIps: authHost.getAuthorizedIPs(),
        //     });
        //     const token = jwt.sign({ username: username, password: password, presenter: true }, jwtCfg.JWT_KEY, {
        //         expiresIn: jwtCfg.JWT_EXP,
        //     });
        //     return res.status(200).json({ message: token });
        // }

        // if (isPeerValid) {
        //     log.debug('PEER LOGIN OK', { ip: ip, authorized: true });
        //     const isPresenter =
        //         config.presenters && config.presenters.list && config.presenters.list.includes(username).toString();
        //     const token = jwt.sign({ username: username, password: password, presenter: isPresenter }, jwtCfg.JWT_KEY, {
        //         expiresIn: jwtCfg.JWT_EXP,
        //     });
        //     return res.status(200).json({ message: token });
        // } else {
        //     return res.status(401).json({ message: 'unauthorized' });
        // }
    });

    // ####################################################
    // KEEP RECORDING ON SERVER DIR
    // ####################################################

    app.post(['/recSync'], (req, res) => {
        // Store recording...
        if (serverRecordingEnabled) {
            //
            const { fileName } = req.query;

            if (!fileName) {
                return res.status(400).send('Filename not provided');
            }

            try {
                if (!fs.existsSync(dir.rec)) {
                    fs.mkdirSync(dir.rec, { recursive: true });
                }
                const filePath = dir.rec + fileName;
                const writeStream = fs.createWriteStream(filePath, { flags: 'a' });

                req.pipe(writeStream);

                writeStream.on('error', (err) => {
                    log.error('Error writing to file:', err.message);
                    res.status(500).send('Internal Server Error');
                });

                writeStream.on('finish', () => {
                    log.debug('File saved successfully:', fileName);
                    res.status(200).send('File uploaded successfully');
                });
            } catch (err) {
                log.error('Error processing upload', err.message);
                res.status(500).send('Internal Server Error');
            }
        }
    });

    // ####################################################
    // REST API
    // ####################################################

    // Login- method POST
    app.post(['/api/user/login'], async (req, res, next) => {

        const { username, password } = checkXSS(req.body);

        try {
            // if (!req.body["g-recaptcha-response"]) {
            //     return res.status(404).json({ message: "مگه رباتی؟"})
            // }
            
            const user = await User.findOne({username});
    
            if(!user){
                // return res.status(404).json({ message: "نام کاربری یا کلمه عبور اشتباه است"})
                const error = new Error("نام کاربری یا کلمه عبور اشتباه است");
                error.statusCode = 422;
                throw error;

            }
                
            const isMatch = await bcrypt.compare(password, user.password);
            const fullname = user.fullname;
            const user_type = user.user_type;
            const organization_code = user.organization_code;
            const idd = user._id.toString();
            if(isMatch){
                const token = jwt.sign(
                    {
                        user: {
                            userId: user._id.toString(),
                            username: user.username,
                            fullname: user.fullname,
                        },
                    },
                    jwtCfg.JWT_KEY
                );
                hostCfg.authenticated = true;
                res.status(200).json({token: token, username: username, fullname: fullname, user_type: user_type, organization_code: organization_code, userId: idd} );
            } else {
                // return res.status(401).json({ message: "نام کاربری یا کلمه عبور اشتباه است" });
                const error = new Error("نام کاربری یا کلمه عبور اشتباه است");
                error.statusCode = 401;
                throw error;
            }
                
            
        } catch (err) {
            // console.log(err);
            // return res.status(500).json({message: "مشکلی از سمت سرور به وجود آمده است"})
            next(err);
        }  
    });

    // Register User - method POST
    app.post(['/api/user/register'], async (req, res, next) => {
        try {
            const { organization_code, user_type, fullname, username, password } = req.body;
    
            const user = await User.findOne({ username });
        
            if (user){
                // return res.status(422).json({message: "کاربری با این نام کاربری موجود است"});
                const error = new Error("کاربری با این نام کاربری موجود است");
                error.statusCode = 422;
                throw error;
            }

            await User.create({ organization_code, user_type, fullname, username, password });
            return res.status(201).json({message: "عضویت با موفقیت انجام شد"});
        } catch (err) {
            // console.log(err);
            // return res.status(500).json({message: "مشکلی پیش آمده"});
            next(err);
        }
    })

    // Delete User - API
    app.delete(['/api/user/delete/:id'], async (req, res, next) => {
        try {
            const user = await User.findById(req.params.id);

            if(!user){
            //   return res.status(404).json({message: "کاربری با این آیدی یافت نشد"});
                const error = new Error("کاربری با این آیدی یافت نشد");
                error.statusCode = 404;
                throw error;
            }
            await User.findByIdAndDelete(req.params.id);
            return res.status(200).json({message: "کاربر با موفقیت حذف شد"});
        } catch (err) {
            // console.log(err);
            // res.status(500).json({message: "مشکلی در سمت سرور به وجود آمده"});
            next(err);
        }
        
    });

    // Change Password - API
    app.put(['/api/user/change-password/:id'], async (req, res, next) => {
        const user = await User.findOne({ _id: req.params.id });

        try {
                if (!user){
                    // return res.status(404).json({message: "کاربری با این آیدی یافت نشد"});
                    const error = new Error("کاربری با این آیدی یافت نشد");
                    error.statusCode = 404;
                    throw error;
                } 
                else {
                    const { oldPassword, newPassword } = checkXSS(req.body);

                    const isMatch = await bcrypt.compare(oldPassword, user.password);

                    if(isMatch){
                        user.password = newPassword;
                        await user.save();
                        return res.status(200).json({message: "کلمه عبور با موفقیت تغییر کرد"});  
                    }
                    else{
                        const error = new Error("کلمه عبور قبلی صحیح نیست");
                        error.statusCode = 422;
                        throw error;
                    }
                    
                }
        } catch (err) {
            // console.log(err);
            // res.status(500).json({message: "مشکلی از سمت سرور پیش آمده"});
            next(err);
        }
    });
    // Api Getting my org
    app.get(['/api/user/partners'], authenticated2, async (req, res, next) => {
        try {
            const userLogged = await User.findOne({username: req.username});
            const partners = await User.find({organization_code: userLogged.organization_code});
            const p = [];
            const m = {};
            for(let i = 0; i < partners.length; i++){
               m.fullname = partners[i].fullname;
               m.username = partners[i].username;
               p.push(m);
            }
            
            if(partners.length > 0) {
                return res.status(200).json({partners: p});
            } else{
                const error = new Error("شما همکار سازمانی ندارید");
                error.statusCode = 404;
                throw error;
            }
        } catch (err) {
            next(err);
        }  
        });

    // Create Didar- API
    app.post(['/api/meeting/add'], async (req, res) => {
        try {
            const { name, date, time, invited, description, presenter } = (req.body);
            await Didar.create(
                {
                    name: name,
                    invited: invited,
                    date: date,
                    time: time,
                    description: description,
                    presenter: presenter
                });
            await SecDidar.create(
                {
                    name: name,
                    invited: invited,
                    date: date,
                    time: time,
                    description: description,
                    presenter: req.username
                });
                return res.status(200).json({message: "جلسه با موفقیت ساخته شد" });
                // res.redirect("/dashboard/:token");

        } catch (err) {
            console.log(err);
            res.status(500).json("خطایی در سمت سرور به وجود آمده است");
        }

    });

    // Get All of Didars
    app.get(['/api/meeting/all'], authenticated2, async (req, res, next) => {
        try {
            const didar = await Didar.find({ presenter: req.username });
            const didar2 = await Didar.find({ invited: req.username });
            if(didar2){
                for(let i = 0; i < didar2.length; i++){
                    didar.push(didar2[i]);
                }
            };

            if(didar.length > 0){
                return res.status(200).json({meetings: didar});
            } else {
                const error = new Error("شما هیچ جلسه‌ای ندارید");
                error.statusCode = 404;
                throw error;
            }
            // if(req.userType == "admin") {
            //     users = await User.find();
            // };
            
        } catch (err) {
            next(err);
        }     
    });

    // request meetings list
    app.get([restApi.basePath + '/meetings'], (req, res) => {
        // Check if endpoint allowed
        if (restApi.allowed && !restApi.allowed.meetings) {
            return res.status(403).json({
                error: 'This endpoint has been disabled. Please contact the administrator for further information.',
            });
        }
        // check if user was authorized for the api call
        const { host, authorization } = req.headers;
        const api = new ServerApi(host, authorization);
        if (!api.isAuthorized()) {
            log.debug('MiroTalk get meetings - Unauthorized', {
                header: req.headers,
                body: req.body,
            });
            return res.status(403).json({ error: 'Unauthorized!' });
        }
        // Get meetings
        const meetings = api.getMeetings(roomList);
        res.json({ meetings: meetings });
        // log.debug the output if all done
        log.debug('MiroTalk get meetings - Authorized', {
            header: req.headers,
            body: req.body,
            meetings: meetings,
        });
    });

    // request meeting room endpoint
    app.post([restApi.basePath + '/meeting'], (req, res) => {
        // Check if endpoint allowed
        if (restApi.allowed && !restApi.allowed.meeting) {
            return res.status(403).json({
                error: 'This endpoint has been disabled. Please contact the administrator for further information.',
            });
        }
        // check if user was authorized for the api call
        const { host, authorization } = req.headers;
        const api = new ServerApi(host, authorization);
        if (!api.isAuthorized()) {
            log.debug('MiroTalk get meeting - Unauthorized', {
                header: req.headers,
                body: req.body,
            });
            return res.status(403).json({ error: 'Unauthorized!' });
        }
        // setup meeting URL
        const meetingURL = api.getMeetingURL();
        res.json({ meeting: meetingURL });
        // log.debug the output if all done
        log.debug('MiroTalk get meeting - Authorized', {
            header: req.headers,
            body: req.body,
            meeting: meetingURL,
        });
    });

    // request join room endpoint
    app.post([restApi.basePath + '/join'], (req, res) => {
        // Check if endpoint allowed
        if (restApi.allowed && !restApi.allowed.join) {
            return res.status(403).json({
                error: 'This endpoint has been disabled. Please contact the administrator for further information.',
            });
        }
        // check if user was authorized for the api call
        const { host, authorization } = req.headers;
        const api = new ServerApi(host, authorization);
        if (!api.isAuthorized()) {
            log.debug('MiroTalk get join - Unauthorized', {
                header: req.headers,
                body: req.body,
            });
            return res.status(403).json({ error: 'Unauthorized!' });
        }
        // setup Join URL
        const joinURL = api.getJoinURL(req.body);
        res.json({ join: joinURL });
        // log.debug the output if all done
        log.debug('MiroTalk get join - Authorized', {
            header: req.headers,
            body: req.body,
            join: joinURL,
        });
    });

    // request token endpoint
    app.post([restApi.basePath + '/token'], (req, res) => {
        // Check if endpoint allowed
        if (restApi.allowed && !restApi.allowed.token) {
            return res.status(403).json({
                error: 'This endpoint has been disabled. Please contact the administrator for further information.',
            });
        }
        // check if user was authorized for the api call
        const { host, authorization } = req.headers;
        const api = new ServerApi(host, authorization);
        if (!api.isAuthorized()) {
            log.debug('MiroTalk get token - Unauthorized', {
                header: req.headers,
                body: req.body,
            });
            return res.status(403).json({ error: 'Unauthorized!' });
        }
        // Get Token
        const token = api.getToken(req.body);
        res.json({ token: token });
        // log.debug the output if all done
        log.debug('MiroTalk get token - Authorized', {
            header: req.headers,
            body: req.body,
            token: token,
        });
    });

    // ####################################################
    // SLACK API
    // ####################################################

    app.post('/slack', (req, res) => {
        if (!slackEnabled) return res.end('`Under maintenance` - Please check back soon.');

        log.debug('Slack', req.headers);

        if (!slackSigningSecret) return res.end('`Slack Signing Secret is empty!`');

        let slackSignature = req.headers['x-slack-signature'];
        let requestBody = qS.stringify(req.body, { format: 'RFC1738' });
        let timeStamp = req.headers['x-slack-request-timestamp'];
        let time = Math.floor(new Date().getTime() / 1000);

        if (Math.abs(time - timeStamp) > 300) return res.end('`Wrong timestamp` - Ignore this request.');

        let sigBaseString = 'v0:' + timeStamp + ':' + requestBody;
        let mySignature = 'v0=' + CryptoJS.HmacSHA256(sigBaseString, slackSigningSecret);

        if (mySignature == slackSignature) {
            let host = req.headers.host;
            let api = new ServerApi(host);
            let meetingURL = api.getMeetingURL();
            log.debug('Slack', { meeting: meetingURL });
            return res.end(meetingURL);
        }
        return res.end('`Wrong signature` - Verification failed!');
    });

    // not match any of page before, so 404 not found
    app.get('*', function (req, res) {
        res.sendFile(views.notFound);
    });

    // ####################################################
    // SERVER CONFIG
    // ####################################################

    function getServerConfig(tunnel = false) {
        return {
            app_version: packageJson.version,
            node_version: process.versions.node,
            cors_options: corsOptions,
            hostConfig: hostCfg,
            jwtCfg: jwtCfg,
            presenters: config.presenters,
            middleware: config.middleware,
            server: host,
            server_tunnel: tunnel,
            rest_api: restApi,
            mediasoup_worker_bin: mediasoup.workerBin,
            mediasoup_server_version: mediasoup.version,
            mediasoup_client_version: mediasoupClient.version,
            mediasoup_listenInfos: config.mediasoup.webRtcTransport.listenInfos,
            ip_lookup_enabled: config.IPLookup.enabled,
            sentry_enabled: sentryEnabled,
            redirect_enabled: config.redirect.enabled,
            slack_enabled: slackEnabled,
            stats_enabled: config.stats.enabled,
            chatGPT_enabled: config.chatGPT.enabled,
            configUI: config.ui,
            serverRec: config?.server?.recording,
        };
    }

    // #######################
    // error handler
    app.use(errorHandler);

    // ####################################################
    // NGROK
    // ####################################################

    async function ngrokStart() {
        try {
            await ngrok.authtoken(config.ngrok.authToken);
            await ngrok.connect(config.server.listen.port);
            const api = ngrok.getApi();
            const list = await api.listTunnels();
            const tunnel = list.tunnels[0].public_url;
            log.info('Server config', getServerConfig(tunnel));
        } catch (err) {
            log.error('Ngrok Start error: ', err.body);
            await ngrok.kill();
            process.exit(1);
        }
    }

    // ####################################################
    // START SERVER
    // ####################################################

    httpsServer.listen(config.server.listen.port, () => {
        log.log(
            `%c
    
        ███████╗██╗ ██████╗ ███╗   ██╗      ███████╗███████╗██████╗ ██╗   ██╗███████╗██████╗ 
        ██╔════╝██║██╔════╝ ████╗  ██║      ██╔════╝██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗
        ███████╗██║██║  ███╗██╔██╗ ██║█████╗███████╗█████╗  ██████╔╝██║   ██║█████╗  ██████╔╝
        ╚════██║██║██║   ██║██║╚██╗██║╚════╝╚════██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██╔══╝  ██╔══██╗
        ███████║██║╚██████╔╝██║ ╚████║      ███████║███████╗██║  ██║ ╚████╔╝ ███████╗██║  ██║
        ╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝      ╚══════╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝ started...
    
        `,
            'font-family:monospace',
        );

        if (config.ngrok.authToken !== '') {
            return ngrokStart();
        }
        log.info('Server config', getServerConfig());
    });

    // ####################################################
    // WORKERS
    // ####################################################

    (async () => {
        try {
            await createWorkers();
        } catch (err) {
            log.error('Create Worker ERR --->', err);
            process.exit(1);
        }
    })();

    async function createWorkers() {
        const { numWorkers } = config.mediasoup;

        const { logLevel, logTags, rtcMinPort, rtcMaxPort } = config.mediasoup.worker;

        log.debug('WORKERS:', numWorkers);

        for (let i = 0; i < numWorkers; i++) {
            let worker = await mediasoup.createWorker({
                logLevel: logLevel,
                logTags: logTags,
                rtcMinPort: rtcMinPort,
                rtcMaxPort: rtcMaxPort,
            });
            worker.on('died', () => {
                log.error('Mediasoup worker died, exiting in 2 seconds... [pid:%d]', worker.pid);
                setTimeout(() => process.exit(1), 2000);
            });
            workers.push(worker);
        }
    }

    async function getMediasoupWorker() {
        const worker = workers[nextMediasoupWorkerIdx];
        if (++nextMediasoupWorkerIdx === workers.length) nextMediasoupWorkerIdx = 0;
        return worker;
    }

    // ####################################################
    // SOCKET IO
    // ####################################################

    io.on('connection', (socket) => {
        socket.on('clientError', (error) => {
            try {
                log.error('Client error', error.message);
                socket.disconnect(true); // true indicates a forced disconnection
            } catch (error) {
                log.error('Error handling Client error', error.message);
            }
        });

        socket.on('error', (error) => {
            try {
                log.error('Socket error', error.message);
                socket.disconnect(true); // true indicates a forced disconnection
            } catch (error) {
                log.error('Error handling socket error', error.message);
            }
        });

        socket.on('createRoom', async ({ room_id }, callback) => {
            socket.room_id = room_id;

            if (roomList.has(socket.room_id)) {
                callback({ error: 'already exists' });
            } else {
                log.debug('Created room', { room_id: socket.room_id });
                const worker = await getMediasoupWorker();
                roomList.set(socket.room_id, new Room(socket.room_id, worker, io));
                callback({ room_id: socket.room_id });
            }
        });

        socket.on('getPeerCounts', async ({}, callback) => {
            if (!roomList.has(socket.room_id)) return;

            const room = roomList.get(socket.room_id);

            const peerCounts = room.getPeersCount();

            log.debug('Peer counts', { peerCounts: peerCounts });

            callback({ peerCounts: peerCounts });
        });

        socket.on('cmd', async (dataObject) => {
            if (!roomList.has(socket.room_id)) return;

            const data = checkXSS(dataObject);

            log.debug('cmd', data);

            const room = roomList.get(socket.room_id);

            switch (data.type) {
                case 'privacy':
                    room.getPeers().get(socket.id).updatePeerInfo({ type: data.type, status: data.active });
                    break;
                case 'ejectAll':
                    const { peer_name, peer_uuid } = data;
                    const isPresenter = await isPeerPresenter(socket.room_id, socket.id, peer_name, peer_uuid);
                    if (!isPresenter) return;
                    break;
                default:
                    break;
                //...
            }

            data.broadcast ? room.broadCast(socket.id, 'cmd', data) : room.sendTo(data.peer_id, 'cmd', data);
        });

        socket.on('roomAction', async (dataObject) => {
            if (!roomList.has(socket.room_id)) return;

            const data = checkXSS(dataObject);

            const isPresenter = await isPeerPresenter(socket.room_id, socket.id, data.peer_name, data.peer_uuid);

            const room = roomList.get(socket.room_id);

            log.debug('Room action:', data);

            switch (data.action) {
                case 'broadcasting':
                    if (!isPresenter) return;
                    room.setIsBroadcasting(data.room_broadcasting);
                    room.broadCast(socket.id, 'roomAction', data.action);
                    break;
                case 'lock':
                    if (!isPresenter) return;
                    if (!room.isLocked()) {
                        room.setLocked(true, data.password);
                        room.broadCast(socket.id, 'roomAction', data.action);
                    }
                    break;
                case 'checkPassword':
                    let roomData = {
                        room: null,
                        password: 'KO',
                    };
                    if (data.password == room.getPassword()) {
                        roomData.room = room.toJson();
                        roomData.password = 'OK';
                    }
                    room.sendTo(socket.id, 'roomPassword', roomData);
                    break;
                case 'unlock':
                    if (!isPresenter) return;
                    room.setLocked(false);
                    room.broadCast(socket.id, 'roomAction', data.action);
                    break;
                case 'lobbyOn':
                    if (!isPresenter) return;
                    room.setLobbyEnabled(true);
                    room.broadCast(socket.id, 'roomAction', data.action);
                    break;
                case 'lobbyOff':
                    if (!isPresenter) return;
                    room.setLobbyEnabled(false);
                    room.broadCast(socket.id, 'roomAction', data.action);
                    break;
                case 'hostOnlyRecordingOn':
                    if (!isPresenter) return;
                    room.setHostOnlyRecording(true);
                    room.broadCast(socket.id, 'roomAction', data.action);
                    break;
                case 'hostOnlyRecordingOff':
                    if (!isPresenter) return;
                    room.setHostOnlyRecording(false);
                    room.broadCast(socket.id, 'roomAction', data.action);
                    break;
                case 'isBanned':
                    log.info('The user has been banned from the room due to spamming messages', data);
                    room.addBannedPeer(data.peer_uuid);
                    break;
                default:
                    break;
            }
            log.debug('Room status', {
                broadcasting: room.isBroadcasting(),
                locked: room.isLocked(),
                lobby: room.isLobbyEnabled(),
                hostOnlyRecording: room.isHostOnlyRecording(),
            });
        });

        socket.on('roomLobby', (dataObject) => {
            if (!roomList.has(socket.room_id)) return;

            const data = checkXSS(dataObject);

            const room = roomList.get(socket.room_id);

            data.room = room.toJson();

            log.debug('Room lobby', {
                peer_id: data.peer_id,
                peer_name: data.peer_name,
                peers_id: data.peers_id,
                lobby: data.lobby_status,
                broadcast: data.broadcast,
            });

            if (data.peers_id && data.broadcast) {
                for (let peer_id in data.peers_id) {
                    room.sendTo(data.peers_id[peer_id], 'roomLobby', data);
                }
            } else {
                room.sendTo(data.peer_id, 'roomLobby', data);
            }
        });

        socket.on('peerAction', async (dataObject) => {
            if (!roomList.has(socket.room_id)) return;

            const data = checkXSS(dataObject);

            log.debug('Peer action', data);

            const presenterActions = [
                'mute',
                'unmute',
                'hide',
                'unhide',
                'stop',
                'start',
                'eject',
                'ban',
                'geoLocation',
            ];

            if (presenterActions.some((v) => data.action === v)) {
                const isPresenter = await isPeerPresenter(
                    socket.room_id,
                    socket.id,
                    data.from_peer_name,
                    data.from_peer_uuid,
                );
                if (!isPresenter) return;
            }

            const room = roomList.get(socket.room_id);

            if (data.action === 'ban') room.addBannedPeer(data.to_peer_uuid);

            data.broadcast
                ? room.broadCast(data.peer_id, 'peerAction', data)
                : room.sendTo(data.peer_id, 'peerAction', data);
        });

        socket.on('updatePeerInfo', (dataObject) => {
            if (!roomList.has(socket.room_id)) return;

            const data = checkXSS(dataObject);

            const room = roomList.get(socket.room_id);

            room.getPeers().get(socket.id).updatePeerInfo(data);

            if (data.broadcast) {
                log.debug('updatePeerInfo broadcast data');
                room.broadCast(socket.id, 'updatePeerInfo', data);
            }
        });

        socket.on('updateRoomModerator', async (dataObject) => {
            if (!roomList.has(socket.room_id)) return;

            const data = checkXSS(dataObject);

            const room = roomList.get(socket.room_id);

            const isPresenter = await isPeerPresenter(socket.room_id, socket.id, data.peer_name, data.peer_uuid);

            if (!isPresenter) return;

            const moderator = data.moderator;

            room.updateRoomModerator(moderator);

            switch (moderator.type) {
                case 'audio_cant_unmute':
                case 'video_cant_unhide':
                case 'screen_cant_share':
                case 'chat_cant_privately':
                case 'chat_cant_chatgpt':
                    room.broadCast(socket.id, 'updateRoomModerator', moderator);
                    break;
                default:
                    break;
            }
        });

        socket.on('updateRoomModeratorALL', async (dataObject) => {
            if (!roomList.has(socket.room_id)) return;

            const data = checkXSS(dataObject);

            const room = roomList.get(socket.room_id);

            const isPresenter = await isPeerPresenter(socket.room_id, socket.id, data.peer_name, data.peer_uuid);

            if (!isPresenter) return;

            const moderator = data.moderator;

            room.updateRoomModeratorALL(moderator);

            room.broadCast(socket.id, 'updateRoomModeratorALL', moderator);
        });

        socket.on('fileInfo', (dataObject) => {
            if (!roomList.has(socket.room_id)) return;

            const data = checkXSS(dataObject);

            if (!isValidFileName(data.fileName)) {
                log.debug('File name not valid', data);
                return;
            }

            log.debug('Send File Info', data);

            const room = roomList.get(socket.room_id);

            data.broadcast ? room.broadCast(socket.id, 'fileInfo', data) : room.sendTo(data.peer_id, 'fileInfo', data);
        });

        socket.on('file', (data) => {
            if (!roomList.has(socket.room_id)) return;

            const room = roomList.get(socket.room_id);

            data.broadcast ? room.broadCast(socket.id, 'file', data) : room.sendTo(data.peer_id, 'file', data);
        });

        socket.on('fileAbort', (dataObject) => {
            if (!roomList.has(socket.room_id)) return;

            const data = checkXSS(dataObject);

            roomList.get(socket.room_id).broadCast(socket.id, 'fileAbort', data);
        });

        socket.on('shareVideoAction', (dataObject) => {
            if (!roomList.has(socket.room_id)) return;

            const data = checkXSS(dataObject);

            if (data.action == 'open' && !isValidHttpURL(data.video_url)) {
                log.debug('Video src not valid', data);
                return;
            }

            log.debug('Share video: ', data);

            const room = roomList.get(socket.room_id);

            data.peer_id == 'all'
                ? room.broadCast(socket.id, 'shareVideoAction', data)
                : room.sendTo(data.peer_id, 'shareVideoAction', data);
        });

        socket.on('wbCanvasToJson', (dataObject) => {
            if (!roomList.has(socket.room_id)) return;

            const data = checkXSS(dataObject);

            const room = roomList.get(socket.room_id);

            // let objLength = bytesToSize(Object.keys(data).length);
            // log.debug('Send Whiteboard canvas JSON', { length: objLength });

            room.broadCast(socket.id, 'wbCanvasToJson', data);
        });

        socket.on('whiteboardAction', (dataObject) => {
            if (!roomList.has(socket.room_id)) return;

            const data = checkXSS(dataObject);

            const room = roomList.get(socket.room_id);

            log.debug('Whiteboard', data);
            room.broadCast(socket.id, 'whiteboardAction', data);
        });

        socket.on('setVideoOff', (dataObject) => {
            if (!roomList.has(socket.room_id)) return;

            const data = checkXSS(dataObject);

            log.debug('Video off data', data.peer_name);

            const room = roomList.get(socket.room_id);

            room.broadCast(socket.id, 'setVideoOff', data);
        });

        socket.on('recordingAction', async (dataObject) => {
            if (!roomList.has(socket.room_id)) return;

            const data = checkXSS(dataObject);

            log.debug('Recording action', data);

            const room = roomList.get(socket.room_id);

            room.broadCast(data.peer_id, 'recordingAction', data);
        });

        socket.on('join', async (dataObject, cb) => {
            if (!roomList.has(socket.room_id)) {
                return cb({
                    error: 'Room does not exist',
                });
            }

            // Get peer IPv4 (::1 Its the loopback address in ipv6, equal to 127.0.0.1 in ipv4)
            const peer_ip = socket.handshake.headers['x-forwarded-for'] || socket.conn.remoteAddress;

            // Get peer Geo Location
            if (config.IPLookup.enabled && peer_ip != '::1') {
                dataObject.peer_geo = await getPeerGeoLocation(peer_ip);
            }

            const data = checkXSS(dataObject);

            log.info('User joined', data);

            let is_presenter = true;

            const { peer_token } = data.peer_info;

            const room = roomList.get(socket.room_id);

            // User Auth required, we check if peer valid
            if (hostCfg.user_auth) {
                // Check JWT
                if (peer_token) {
                    try {
                        const { username, password, presenter } = checkXSS(jwt.verify(peer_token, jwtCfg.JWT_KEY));

                        const isPeerValid = await isAuthPeer(username, password);

                        is_presenter =
                            presenter === '1' ||
                            presenter === 'true' ||
                            (config.presenters.join_first && room.getPeers().size === 0);

                        log.debug('[Join] - HOST PROTECTED - USER AUTH check peer', {
                            ip: peer_ip,
                            peer_username: username,
                            peer_password: password,
                            peer_valid: isPeerValid,
                            peer_presenter: is_presenter,
                        });

                        if (!isPeerValid) {
                            // redirect peer to login page
                            return cb('unauthorized');
                        }
                    } catch (err) {
                        log.error('[Join] - JWT error', { error: err.message, token: peer_token });
                        return cb('unauthorized');
                    }
                } else {
                    return cb('unauthorized');
                }
            }

            // check if banned...
            const peerUUID = data.peer_info.peer_uuid;
            if (room.isBanned(peerUUID)) {
                const { peer_name, peer_uuid, os_name, os_version, browser_name, browser_version } = data.peer_info;
                log.info('[Join] - peer is banned!', {
                    room_id: data.room_id,
                    peer: {
                        name: peer_name,
                        uuid: peer_uuid,
                        os_name: os_name,
                        os_version: os_version,
                        browser_name: browser_name,
                        browser_version: browser_version,
                    },
                });
                return cb('isBanned');
            }

            room.addPeer(new Peer(socket.id, data));

            const activeRooms = getActiveRooms();

            log.info('[Join] - current active rooms', activeRooms);

            if (!(socket.room_id in presenters)) presenters[socket.room_id] = {};

            const peer = room.getPeers()?.get(socket.id)?.peer_info;

            const peer_id = peer && peer.peer_id;
            const peer_name = peer && peer.peer_name;
            const peer_uuid = peer && peer.peer_uuid;

            // Set the presenters
            const presenter = {
                peer_ip: peer_ip,
                peer_name: peer_name,
                peer_uuid: peer_uuid,
                is_presenter: is_presenter,
            };
            // first we check if the username match the presenters username
            if (config.presenters && config.presenters.list && config.presenters.list.includes(peer_name)) {
                presenters[socket.room_id][socket.id] = presenter;
            } else {
                // if not match the presenters username, the first one join room is the presenter
                if (Object.keys(presenters[socket.room_id]).length === 0) {
                    presenters[socket.room_id][socket.id] = presenter;
                }
            }

            log.info('[Join] - Connected presenters grp by roomId', presenters);

            const isPresenter = peer_token
                ? is_presenter
                : await isPeerPresenter(socket.room_id, socket.id, peer_name, peer_uuid);

            room.getPeers().get(socket.id).updatePeerInfo({ type: 'presenter', status: isPresenter });

            log.info('[Join] - Is presenter', {
                roomId: socket.room_id,
                peer_name: peer_name,
                peer_presenter: isPresenter,
            });

            if (room.isLocked() && !isPresenter) {
                log.debug('The user was rejected because the room is locked, and they are not a presenter');
                return cb('isLocked');
            }

            if (room.isLobbyEnabled() && !isPresenter) {
                log.debug(
                    'The user is currently waiting to join the room because the lobby is enabled, and they are not a presenter',
                );
                room.broadCast(socket.id, 'roomLobby', {
                    peer_id: peer_id,
                    peer_name: peer_name,
                    lobby_status: 'waiting',
                });
                return cb('isLobby');
            }

            cb(room.toJson());
        });

        socket.on('getRouterRtpCapabilities', (_, callback) => {
            if (!roomList.has(socket.room_id)) {
                return callback({ error: 'Room not found' });
            }

            const room = roomList.get(socket.room_id);

            log.debug('Get RouterRtpCapabilities', getPeerName(room));
            try {
                callback(room.getRtpCapabilities());
            } catch (err) {
                callback({
                    error: err.message,
                });
            }
        });

        socket.on('getProducers', () => {
            if (!roomList.has(socket.room_id)) return;

            const room = roomList.get(socket.room_id);

            log.debug('Get producers', getPeerName(room));

            // send all the current producer to newly joined member
            const producerList = room.getProducerListForPeer();

            socket.emit('newProducers', producerList);
        });

        socket.on('createWebRtcTransport', async (_, callback) => {
            if (!roomList.has(socket.room_id)) {
                return callback({ error: 'Room not found' });
            }

            const room = roomList.get(socket.room_id);

            log.debug('Create webrtc transport', getPeerName(room));
            try {
                const { params } = await room.createWebRtcTransport(socket.id);
                callback(params);
            } catch (err) {
                log.error('Create WebRtc Transport error', err.message);
                callback({
                    error: err.message,
                });
            }
        });

        socket.on('connectTransport', async ({ transport_id, dtlsParameters }, callback) => {
            if (!roomList.has(socket.room_id)) {
                return callback({ error: 'Room not found' });
            }

            const room = roomList.get(socket.room_id);

            log.debug('Connect transport', getPeerName(room));

            await room.connectPeerTransport(socket.id, transport_id, dtlsParameters);

            callback('success');
        });

        socket.on('produce', async ({ producerTransportId, kind, appData, rtpParameters }, callback) => {
            if (!roomList.has(socket.room_id)) {
                return callback({ error: 'Room not found' });
            }

            const room = roomList.get(socket.room_id);

            const peer_name = getPeerName(room, false);

            // peer_info audio Or video ON
            const data = {
                peer_name: peer_name,
                peer_id: socket.id,
                kind: kind,
                type: appData.mediaType,
                status: true,
            };

            await room.getPeers().get(socket.id).updatePeerInfo(data);

            const producer_id = await room.produce(
                socket.id,
                producerTransportId,
                rtpParameters,
                kind,
                appData.mediaType,
            );

            log.debug('Produce', {
                kind: kind,
                type: appData.mediaType,
                peer_name: peer_name,
                peer_id: socket.id,
                producer_id: producer_id,
            });

            // add & monitor producer audio level
            if (kind === 'audio') {
                room.addProducerToAudioLevelObserver({ producerId: producer_id });
            }

            callback({
                producer_id,
            });
        });

        socket.on('consume', async ({ consumerTransportId, producerId, rtpCapabilities }, callback) => {
            if (!roomList.has(socket.room_id)) {
                return callback({ error: 'Room not found' });
            }

            const room = roomList.get(socket.room_id);

            const params = await room.consume(socket.id, consumerTransportId, producerId, rtpCapabilities);

            log.debug('Consuming', {
                peer_name: getPeerName(room, false),
                producer_id: producerId,
                consumer_id: params ? params.id : undefined,
            });

            callback(params);
        });

        socket.on('producerClosed', (data) => {
            if (!roomList.has(socket.room_id)) return;

            log.debug('Producer close', data);

            const room = roomList.get(socket.room_id);

            // peer_info audio Or video OFF
            room.getPeers().get(socket.id).updatePeerInfo(data);
            room.closeProducer(socket.id, data.producer_id);
        });

        socket.on('resume', async (_, callback) => {
            await consumer.resume();
            callback();
        });

        socket.on('getRoomInfo', async (_, cb) => {
            if (!roomList.has(socket.room_id)) return;

            const room = roomList.get(socket.room_id);

            log.debug('Send Room Info to', getPeerName(room));
            cb(room.toJson());
        });

        socket.on('refreshParticipantsCount', () => {
            if (!roomList.has(socket.room_id)) return;

            const room = roomList.get(socket.room_id);

            const data = {
                room_id: socket.room_id,
                peer_counts: room.getPeers().size,
            };
            log.debug('Refresh Participants count', data);
            room.broadCast(socket.id, 'refreshParticipantsCount', data);
        });

        socket.on('message', (dataObject) => {
            if (!roomList.has(socket.room_id)) return;

            const data = checkXSS(dataObject);

            const room = roomList.get(socket.room_id);

            // check if the message coming from real peer
            const realPeer = isRealPeer(data.peer_name, socket.id, socket.room_id);
            if (!realPeer) {
                const peer_name = getPeerName(room, false);
                log.debug('Fake message detected', {
                    realFrom: peer_name,
                    fakeFrom: data.peer_name,
                    msg: data.peer_msg,
                });
                return;
            }

            log.info('message', data);

            data.to_peer_id == 'all'
                ? room.broadCast(socket.id, 'message', data)
                : room.sendTo(data.to_peer_id, 'message', data);
        });

        socket.on('getChatGPT', async ({ time, room, name, prompt }, cb) => {
            if (!roomList.has(socket.room_id)) return;
            if (!config.chatGPT.enabled) return cb('ChatGPT seems disabled, try later!');
            try {
                // https://platform.openai.com/docs/api-reference/completions/create
                const completion = await chatGPT.completions.create({
                    model: config.chatGPT.model || 'gpt-3.5-turbo-instruct',
                    prompt: prompt,
                    max_tokens: config.chatGPT.max_tokens,
                    temperature: config.chatGPT.temperature,
                });
                const response = completion.choices[0].text;
                log.info('ChatGPT', {
                    time: time,
                    room: room,
                    name: name,
                    prompt: prompt,
                    response: response,
                });
                cb(response);
            } catch (error) {
                if (error.name === 'APIError') {
                    log.error('ChatGPT', {
                        name: error.name,
                        status: error.status,
                        message: error.message,
                        code: error.code,
                        type: error.type,
                    });
                    cb(error.message);
                } else {
                    // Non-API error
                    log.error('ChatGPT', error);
                    cb(error.message);
                }
            }
        });

        socket.on('disconnect', async () => {
            if (!roomList.has(socket.room_id)) return;

            const room = roomList.get(socket.room_id);

            const peer = room.getPeers()?.get(socket.id)?.peer_info;

            const peerName = (peer && peer.peer_name) || '';
            const peerUuid = (peer && peer.peer_uuid) || '';

            const isPresenter = await isPeerPresenter(socket.room_id, socket.id, peerName, peerUuid);

            log.debug('[Disconnect] - peer name', peerName);

            room.removePeer(socket.id);

            if (room.getPeers().size === 0) {
                //
                roomList.delete(socket.room_id);

                const activeRooms = getActiveRooms();

                log.info('[Disconnect] - Last peer - current active rooms', activeRooms);

                delete presenters[socket.room_id];
                log.info('[Disconnect] - Last peer - current presenters grouped by roomId', presenters);
            }

            room.broadCast(socket.id, 'removeMe', removeMeData(room, peerName, isPresenter));

            removeIP(socket);
        });

        socket.on('exitRoom', async (_, callback) => {
            if (!roomList.has(socket.room_id)) {
                return callback({
                    error: 'Not currently in a room',
                });
            }

            const room = roomList.get(socket.room_id);

            const peer = room.getPeers()?.get(socket.id)?.peer_info;

            const peerName = (peer && peer.peer_name) || '';
            const peerUuid = (peer && peer.peer_uuid) || '';

            const isPresenter = await isPeerPresenter(socket.room_id, socket.id, peerName, peerUuid);

            log.debug('Exit room', peerName);

            // close transports
            await room.removePeer(socket.id);

            room.broadCast(socket.id, 'removeMe', removeMeData(room, peerName, isPresenter));

            if (room.getPeers().size === 0) {
                //
                roomList.delete(socket.room_id);

                delete presenters[socket.room_id];

                log.info('[REMOVE ME] - Last peer - current presenters grouped by roomId', presenters);

                const activeRooms = getActiveRooms();

                log.info('[REMOVE ME] - Last peer - current active rooms', activeRooms);
            }

            socket.room_id = null;

            removeIP(socket);

            callback('Successfully exited room');
        });

        // common
        function getPeerName(room, json = true) {
            try {
                let peer_name = (room && room.getPeers()?.get(socket.id)?.peer_info?.peer_name) || 'undefined';

                if (json) {
                    return {
                        peer_name: peer_name,
                    };
                }
                return peer_name;
            } catch (err) {
                log.error('getPeerName', err);
                return json ? { peer_name: 'undefined' } : 'undefined';
            }
        }

        function isRealPeer(name, id, roomId) {
            const room = roomList.get(roomId);

            let peerName = (room && room.getPeers()?.get(id)?.peer_info?.peer_name) || 'undefined';

            return peerName == name;
        }

        function isValidFileName(fileName) {
            const invalidChars = /[\\\/\?\*\|:"<>]/;
            return !invalidChars.test(fileName);
        }

        function isValidHttpURL(input) {
            const pattern = new RegExp(
                '^(https?:\\/\\/)?' + // protocol
                    '((([a-z\\d]([a-z\\d-]*[a-z\\d])*)\\.)+[a-z]{2,}|' + // domain name
                    '((\\d{1,3}\\.){3}\\d{1,3}))' + // OR ip (v4) address
                    '(\\:\\d+)?(\\/[-a-z\\d%_.~+]*)*' + // port and path
                    '(\\?[;&a-z\\d%_.~+=-]*)?' + // query string
                    '(\\#[-a-z\\d_]*)?$',
                'i',
            ); // fragment locator
            return pattern.test(input);
        }

        function removeMeData(room, peerName, isPresenter) {
            const roomId = room && socket.room_id;
            const peerCounts = room && room.getPeers().size;
            log.debug('[REMOVE ME] - DATA', {
                roomId: roomId,
                name: peerName,
                isPresenter: isPresenter,
                count: peerCounts,
            });
            return {
                room_id: roomId,
                peer_id: socket.id,
                peer_name: peerName,
                peer_counts: peerCounts,
                isPresenter: isPresenter,
            };
        }

        function bytesToSize(bytes) {
            let sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
            if (bytes == 0) return '0 Byte';
            let i = parseInt(Math.floor(Math.log(bytes) / Math.log(1024)));
            return Math.round(bytes / Math.pow(1024, i), 2) + ' ' + sizes[i];
        }
    });

    async function isPeerPresenter(room_id, peer_id, peer_name, peer_uuid) {
        try {
            if (
                config.presenters &&
                config.presenters.join_first &&
                (!presenters[room_id] || !presenters[room_id][peer_id])
            ) {
                // Presenter not in the presenters config list, disconnected, or peer_id changed...
                for (const [existingPeerID, presenter] of Object.entries(presenters[room_id] || {})) {
                    if (presenter.peer_name === peer_name) {
                        log.info('Presenter found', {
                            room: room_id,
                            peer_id: existingPeerID,
                            peer_name: peer_name,
                        });
                        return true;
                    }
                }
                return false;
            }

            const isPresenter =
                (config.presenters &&
                    config.presenters.join_first &&
                    typeof presenters[room_id] === 'object' &&
                    Object.keys(presenters[room_id][peer_id]).length > 1 &&
                    presenters[room_id][peer_id]['peer_name'] === peer_name &&
                    presenters[room_id][peer_id]['peer_uuid'] === peer_uuid) ||
                (config.presenters && config.presenters.list && config.presenters.list.includes(peer_name));

            log.debug('isPeerPresenter', {
                room_id: room_id,
                peer_id: peer_id,
                peer_name: peer_name,
                peer_uuid: peer_uuid,
                isPresenter: isPresenter,
            });

            return isPresenter;
        } catch (err) {
            log.error('isPeerPresenter', err);
            return false;
        }
    }

    async function isAuthPeer(username, password) {
        if (hostCfg.users_from_db && hostCfg.users_api_endpoint) {
            try {
                const response = await axios.post(hostCfg.users_api_endpoint, {
                    email: username,
                    password: password,
                    api_secret_key: hostCfg.users_api_secret_key,
                });
                return response.data && response.data.message === true;
            } catch (error) {
                log.error('AXIOS isAuthPeer error', error.message);
                return false;
            }
        } else {
            return (
                hostCfg.users && hostCfg.users.some((user) => user.username === username && user.password === password)
            );
        }
        // const user = User.getOneUser(username);
        // if(!user){
        //     return false;
        // }    
        // if(user.password != password){
        //     return false;
        // } else {
        //     return true;
        // }
    }

    function getActiveRooms() {
        const roomIds = Array.from(roomList.keys());
        const roomPeersArray = roomIds.map((roomId) => {
            const room = roomList.get(roomId);
            const peerCount = room ? room.getPeers().size : 0;
            const broadcasting = room ? room.isBroadcasting() : false;
            return {
                room: roomId,
                broadcasting: broadcasting,
                peers: peerCount,
            };
        });
        return roomPeersArray;
    }

    async function getPeerGeoLocation(ip) {
        const endpoint = config.IPLookup.getEndpoint(ip);
        log.debug('Get peer geo', { ip: ip, endpoint: endpoint });
        return axios
            .get(endpoint)
            .then((response) => response.data)
            .catch((error) => log.error(error));
    }

    function getIP(req) {
        return req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    }
    function allowedIP(ip) {
        return authHost != null && authHost.isAuthorizedIP(ip);
    }
    function removeIP(socket) {
        if (hostCfg.protected) {
            let ip = socket.handshake.address;
            if (ip && allowedIP(ip)) {
                authHost.deleteIP(ip);
                hostCfg.authenticated = false;
                log.info('Remove IP from auth', {
                    ip: ip,
                    authorizedIps: authHost.getAuthorizedIPs(),
                });
            }
        }
    }
}
