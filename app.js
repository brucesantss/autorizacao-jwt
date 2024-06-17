//importações
import 'dotenv/config';
import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

import User from './models/UserSchema.js';

//definições base
const app = express();
const port = process.env.PORT || 8080;
app.use(express.json());

//rota pública - sem login ou autorização
app.get('/', (req, res) => {
    return res.status(200).json({ msg: 'bem-vindo a nossa api!' })
})

//rota privada - apenas com login
app.get('/user/:id', checkToken, async (req, res) => {
    const { id } = req.params;
  
    try {
      if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({ msg: 'id de usuário inválido.' });
      }
      const objectId = await new mongoose.Types.ObjectId(id);

      const user = await User.findById(objectId, '-password');
  
      if (!user) {
        return res.status(404).json({ msg: 'Usuário não encontrado.' });
      }
  
      res.status(200).json(user);
    } catch (error) {
      console.error(error);
      res.status(500).json({ msg: 'erro no servidor.' });
    }
  });

  function checkToken(req, res, next){
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if(!token){
        return res.status(401).json({ msg: 'acesso negado!' })
    }

    try{
       const secret = process.env.SECRET; 

       jwt.verify(token, secret);

       next();
    }catch(err){
        return res.status(400).json({ msg: 'token inválido!' })
    }
  }

//cadastro usuário
app.post('/auth/cadastro', async (req, res) => {
    const { name, email, password, confirmPassword } = req.body;

    //validações
    if(!name){
        return res.status(422).json({ msg: 'o nome é obrigatório!' });
    }
    if(!email){
        return res.status(422).json({ msg: 'o email é obrigatório!' });
    }
    if(!password){
        return res.status(422).json({ msg: 'a senha é obrigatória!' });
    }
    if(password !== confirmPassword){
        return res.status(422).json({ msg: 'as senhas não coincidem!' });
    }

    const userExists = await User.findOne({email: email});

    if(userExists){
        return res.status(422).json({ msg: 'esse email já está sendo usado!' });
    }

    //criando senha
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    //criando usuário
    const user = new User({
        name,
        email,
        password: passwordHash
    });

    try{
        await user.save();
        return res.status(201).json({ msg: 'usuário criado com sucesso.' })
    }catch(err){
        console.log(err);
        return res.status(500).json({ msg: 'problemas no servidor.' })
    }

});

//login usuário
app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;

    //validações
    if(!email){
        return res.status(422).json({ msg: 'o email é obrigatório!' });
    }
    if(!password){
        return res.status(422).json({ msg: 'a senha é obrigatória!' });
    }

    //checar se o usuário existe

    const user = await User.findOne({email: email});    

    if(!user){
        return res.status(422).json({ msg: 'usuário não encontrado!' });
    }

    //checar senha
    const checkPassword = await bcrypt.compare(password, user.password);

    if(!checkPassword){
        return res.status(404).json({ msg: 'senha inválida!' });
    }

    try{
        const secret = process.env.SECRET;

        const token = jwt.sign({
            id: user._id,
            
        }, secret)

        return res.status(200).json({ msg: 'autenticação realizada com sucesso!', token });
    }catch(err){
        console.log(err);
        return res.status(500).json({ msg: 'problemas no servidor.' })
    }
})

//conexão no banco de dados
mongoose.connect(process.env.DB_CONEXAO);
const db = mongoose.connection;

//aviso de conexão bem-sucedida no banco de dados
db.on('error', () => console.log('bank status: offline'));
db.once('open', () => console.log('bank status: on-line'));

//ligando o server
app.listen(port, () => {
    console.log('server status: on-line');
})
