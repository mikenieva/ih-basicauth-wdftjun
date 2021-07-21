const session = require('express-session')
const MongoStore = require("connect-mongo")


module.exports = app => {

  // PARA GESTIONAR LA SEGURIDAD EN HEROKU.COM
  app.set("trust proxy", 1)

  // INSERTAR LA SESIÓN
  app.use(
    session({
      secret: process.env.SESS_SECRET,
      resave: true,
      saveUninitialized: false,
      cookie: {
        sameSite: process.env.NODE_ENV === 'production' ? "none" : "lax",
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 600000
      },
      store: MongoStore.create({
        mongoUrl: process.env.MONGODB_URI
      })
    })
  )
}
