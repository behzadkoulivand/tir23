const jwt = require("jsonwebtoken");

exports.authenticated = (req, res, next) => {
    const authHeader = req.get("Authorization");

    try {
        if (!authHeader) {
            const error = new Error("شما ابتدا باید وارد شوید");
            error.statusCode = 401;
            throw error;
            // res.status(401).json("شما ابتدا باید وارد شوید");
        }

        // const token = authHeader.split(" ")[1]; //Bearer Token => ['Bearer', token]
        const token = req.params.token;

        const decodedToken = jwt.verify(token, 'mirotalksfu_jwt_secret');

        if (!decodedToken) {
            const error = new Error("شما مجوز کافی ندارید");
            error.statusCode = 401;
            throw error;
            // res.status(401).json("شما مجوز ورود ندارید");
        }

        req.username = decodedToken.user.username;
        req.userId = decodedToken.user.userId;
        req.userType = decodedToken.user.userType;
        next();
    } catch (err) {
        next(err);
    }
};

exports.authenticated2 = (req, res, next) => {
    const authHeader = req.get("Authorization");

    try {
        if (!authHeader) {
            // const error = new Error("مجوز کافی ندارید");
            // error.statusCode = 401;
            // throw error;
            res.status(401).json("شما ابتدا باید وارد شوید");
        }

        const token = authHeader.split(" ")[1]; //Bearer Token => ['Bearer', token]
        // const token = req.params.token;

        const decodedToken = jwt.verify(token, 'mirotalksfu_jwt_secret');

        if (!decodedToken) {
            const error = new Error("شما مجوز کافی ندارید");
            error.statusCode = 401;
            throw error;
            // res.status(401).json("شما مجوز ورود ندارید");
        }

        req.username = decodedToken.user.username;
        req.userId = decodedToken.user.userId;
        req.userType = decodedToken.user.userType;
        next();
    } catch (err) {
        next(err);
    }
};