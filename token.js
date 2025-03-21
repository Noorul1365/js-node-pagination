const jwt = require("jsonwebtoken");
const sellerModel = require("../models/seller");
const adminModel = require("../models/admin");
const doctorModel = require("../models/doctor");
const userModel = require("../models/user");
const userToken = require("../models/userToken");
require("dotenv").config();


module.exports.isSellerLoggedIn = async (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) {
    return res.send({ code: 400, message: "No token provided" });
  }

  try {
    // Decode the token using the JWT secret
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);

    if (!decodedToken) {
      return res.send({ code: 400, message: "Failed to authenticate token" });
    }

    if (!decodedToken.user_id) {
      return res.send({
        code: 400,
        message: "Cannot find user_id in decoded token",
      });
    }

    // Fetch the seller using the decoded user_id
    const foundSeller = await sellerModel.findById(decodedToken.user_id);

    if (!foundSeller) {
      return res.send({ code: 400, message: "Seller not found" });
    }
 
    // console.log(foundSeller,"found seller");
    // Set req.sellerID to the original seller ID if the seller is a manager
    req.sellerID = foundSeller.sellerType === "manager" && foundSeller.parentSeller
      ? foundSeller.parentSeller
      : foundSeller._id;

    // Set req.managerID to the manager's ID if the seller is a manager
    req.managerID = foundSeller.sellerType === "manager" ? foundSeller._id : null;

    next(); // Proceed to the next middleware or route handler
  } catch (err) {
    if (err.name === "JsonWebTokenError") {
      return res.send({ code: 400, message: "Invalid token signature" });
    } else if (err.name === "TokenExpiredError") {
      return res.send({ code: 400, message: "Token has expired" });
    } else {
      return res.send({ code: 500, message: "Internal server error" });
    }
  }
};


// module.exports.isSellerLoggedIn = async (req, res, next) => {
//   const token = req.headers.authorization;

//   if (!token) {
//     return res.send({ code: 400, message: "No token provided" });
//   }

//   try {
//     const decodedToken = jwt.verify(token, process.env.JWT_SECRET); // Use  actual secret key instead of "auto"
//     // const decodedToken = jwt.verify(token, process.env.JWT_SECRET); // Use  actual secret key instead of "auto"

//     if (!decodedToken) {
//       return res.send({ code: 400, message: "Failed to authenticate token" });
//     }

//     if (!decodedToken.user_id) {
//       return res.send({
//         code: 400,
//         message: "Cannot find user_id in decoded token",
//       });
//     }

//     const foundSeller = await sellerModel.findById(decodedToken.user_id);

//     if (!foundSeller) {
//       return res.send({ code: 400, message: "Seller not found" });
//     }

//     req.userID = decodedToken.user_id;
//     req.sellerID = decodedToken.user_id;
//     next();
//   } catch (err) {
//     if (err.name === "JsonWebTokenError") {
//       return res.send({ code: 400, message: "Invalid token signature" });
//     } else if (err.name === "TokenExpiredError") {
//       return res.send({ code: 400, message: "Token has expired" });
//     } else {
//       return res.send({ code: 500, message: "Internal server error" });
//     }
//   }
// };

module.exports.isAdminLoggedIn = async (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) {
    return res.send({ code: 400, message: "No token provided" });
  }

  try {
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET); // Use  actual secret key instead of "auto"
    // const decodedToken = jwt.verify(token, process.env.JWT_SECRET); // Use  actual secret key instead of "auto"

    if (!decodedToken) {
      return res.send({ code: 400, message: "Failed to authenticate token" });
    }

    if (!decodedToken.admin_id) {
      return res.send({
        code: 400,
        message: "Cannot find admin_id in decoded token",
      });
    }

    const foundAdmin = await adminModel.findById(decodedToken.admin_id);

    if (!foundAdmin) {
      return res.send({ code: 400, message: "Admin not found" });
    }

    req.adminID = decodedToken.admin_id;
    next();
  } catch (err) {
    if (err.name === "JsonWebTokenError") {
      return res.send({ code: 400, message: "Invalid token signature" });
    } else if (err.name === "TokenExpiredError") {
      return res.send({ code: 400, message: "Token has expired" });
    } else {
      return res.send({ code: 500, message: "Internal server error" });
    }
  }
};

module.exports.isDoctorLoggedIn = async (req, res, next) => {
  const token = req.headers.authorization;

  // console.log("token", token);

  if (!token) {
    return res.send({ code: 400, message: "No token provided" });
  }

  try {
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET); // Use  actual secret key instead of "auto"
    // const decodedToken = jwt.verify(token, process.env.JWT_SECRET); // Use  actual secret key instead of "auto"

    if (!decodedToken) {
      return res.send({ code: 400, message: "Failed to authenticate token" });
    }

    if (!decodedToken.doctor_id) {
      return res.send({
        code: 400,
        message: "Cannot find doctor_id in decoded token",
      });
    }

    if(decodedToken.status == "Inactive"){
      return res.send({
        code: 403,
        message: "Doctor account is inactive, please connect with administrator.",
      });
    }

    const foundDoctor = await doctorModel.findById(decodedToken.doctor_id);

    if (!foundDoctor) {
      return res.send({ code: 400, message: "Doctor not found" });
    }

    req.doctorID = decodedToken.doctor_id;
    next();
  } catch (err) {
    if (err.name === "JsonWebTokenError") {
      return res.send({ code: 400, message: "Invalid token signature" });
    } else if (err.name === "TokenExpiredError") {
      return res.send({ code: 400, message: "Token has expired" });
    } else {
      return res.send({ code: 500, message: "Internal server error" });
    }
  }
};

module.exports.isUserLoggedIn = async (req, res, next) => {
  try {

    
    const token = req.headers.authorization;

    if (!token) {
      return res.status(401).json({ code: 401, message: "No token provided" });
    }

    // Verify the token
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);

    // console.log("this is decoded token", decodedToken);

    if (!decodedToken) {
      return res
        .status(400)
        .json({ code: 400, message: "Failed to authenticate token" });
    }

    // Attach user ID to request and proceed
    if (decodedToken?.user_id) {
      const foundUser = await userModel.findById(decodedToken.user_id);

      if (!foundUser) {
        return res.status(401).send({ code: 401, message: "User not found" });
      }

      if(foundUser.status== false){
        return res.status(401).send({code:401, message:'User not authorized.'})
      }


      const foundToken = await userToken.findOne({user_id:decodedToken.user_id, token:token})
      
      if(!foundToken){
        return res.status(401).send({code:401, message:'Token not found in DB'})
      } else {
        req.userID = decodedToken.user_id;
        next();
      }
      
    }
  } catch (error) {
    console.error("Error in token verification:", error.message);
    return res.status(500).json({ code: 500, message: "Internal Server Error" });
  }
};


// module.exports.isUserLoggedIn = (req, res, next) => {
//   const token = req.headers.authorization;

//   if (!token) {
//     return res.json({ code: 400, message: "No token provided" });
//   }

//   let decodedToken = jwt.verify(token, process.env.JWT_SECRET);
//   // console.log("this is decoded token", decodedToken);
//   if (!decodedToken) {
//     return res.json({ code: 400, message: "Failed to authenticate token" });
//   } else if (decodedToken?.user_id) {
//     req.userID = decodedToken.user_id
//     next();
//   }
// };
