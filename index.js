const express = require('express')

const cert = require('./crtgenerate.js')

const config = {
  serPort: 12152,
  RootcommonName: "",
  organizationName: ""
}

if (config.RootcommonName || config.organizationName) {
  cert.setDefault({organizationName, RootcommonName} = config)
}

const app = express()

app.use(express.static(__dirname + '/web'))
app.listen(config.serPort, ()=>{
  console.log("server on port: " + config.serPort)
})

app.get("/crt", (req, res)=>{
  let domain = req.query.domain
  console.log(domain)
  let {path} = cert.Domain(domain)
  res.end(path?"生成证书成功： " + path:"证书已存在")  
})