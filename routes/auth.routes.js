const router = require("express").Router()
const bcryptjs = require("bcryptjs")

const mongoose = require("mongoose")

const User = require('./../models/User.model')


// GET - Display the signup for
router.get("/signup", (req, res) => {
  res.render("auth/signup")
})

// POST - Process form data
router.post("/signup", (req, res) => {

  // EXTRACCIÓN DE VALORES A UNA VARIABLE
  const { username, email, password } = req.body

  // VALIDAR QUE NO LLEGUEN DATOS VACÍOS
  if(!username || !email || !password ){
    return res.render('auth/signup', {
      msg: "Todos los campos son obligatorios"
    })
  }

  // VERIFICAR QUE EL PASSWORD ES FUERTE (TIENE UNA COMBINACIÓN DÍFICIL DE LEER)
    const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;

    // Si el password no cumple con las expectativas del regex
    if(!regex.test(password)){
      return res.status(500).render("auth/signup", {
        msg: "El password debe tener 6 caracteres mínimo y debe contener al menos un número, una minúscula y una mayúscula."
      })
    }




  // ENCRIPTACIÓN
  bcryptjs
    .genSalt(10)
    .then(salt => bcryptjs.hash(password, salt))
    .then(hashedPassword => {
      return User.create({ 
        username, 
        email,  
        passwordHash: hashedPassword
      })
    })
    .then(usuarioCreado => {
      console.log("El usuario que creamos fue:", usuarioCreado)

      res.redirect('/userprofile')
    })
    .catch(e => {
      if(e instanceof mongoose.Error.ValidationError){
        res.status(500).render("auth/signup", {
          msg: "Usa un email válido"
        })
      } else if (e.code === 11000) {
          res.status(500).render("auth/signup", {
            msg: "El usuario y el correo ya existen. Intenta uno nuevo."
          })
      }
    })


})


// GET Profile Page for current user

router.get('/userprofile', (req, res) => {
    res.render("users/user-profile")
})



module.exports = router





