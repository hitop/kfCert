'use strict'

const forge = require('node-forge')
const pki = forge.pki
const fs = require('fs')
const path = require('path')
const mkdirp = require('mkdirp')

const certsPath = path.join(__dirname, './certs')
const rootCAcrt = path.join(__dirname, './certs/rootCA.crt')
const rootCAkey = path.join(__dirname, './certs/rootCA.key')

var defaultAttrs = [
      { name: 'countryName', value: 'CN' },
      { shortName: 'ST', value: 'GuangDong' },
      { name: 'localityName', value: 'ShenZhen' },
      { name: 'organizationName', value: "kfCert" },
      { shortName: 'OU', value: "kfCert" }
    ]

function isIpDomain(domain = '') {
  const ipReg = /^\d+?\.\d+?\.\d+?\.\d+?$/
  return ipReg.test(domain)
}

function getExtensionSAN(domain = '') {
  if (isIpDomain(domain)) {
    return {
      name: 'subjectAltName',
      altNames: [{ type: 7, ip: domain }]
    }
  } else {
    return {
      name: 'subjectAltName',
      altNames: [{ type: 2, value: domain }]
    }
  }
}

module.exports = {
  summary: '生成证书',
  setDefault({organizationName, RootcommonName}) {
    console.log(organizationName)
    if (organizationName) {
      defaultAttrs = [
        { name: 'countryName', value: 'CN' },
        { shortName: 'ST', value: 'GuangDong' },
        { name: 'localityName', value: 'ShenZhen' },
        { name: 'organizationName', value: organizationName },
        { shortName: 'OU', value: organizationName }
      ]
      this.Root(true, RootcommonName)
    }
  },
  Root(forcenew=false, commonName="kfCert"){
    if (!forcenew && fs.existsSync(rootCAcrt) && fs.existsSync(rootCAkey)) {
      console.log('rootCA already generate at: ' + certsPath)  
      return true
    } else {
      if(!fs.existsSync(certsPath)) mkdirp.sync(certsPath)
      console.log('new root cert will generate at: ' + certsPath)
    }
    var keys = pki.rsa.generateKeyPair(2048)
    var cert = pki.createCertificate() 
    cert.publicKey = keys.publicKey
    cert.serialNumber = (new Date()).getTime() + ''

    cert.validity.notBefore = new Date()
    cert.validity.notAfter = new Date()
    cert.validity.notAfter.setFullYear(cert.validity.notAfter.getFullYear() + 50)

    var attrs = defaultAttrs.concat([
      { name: 'commonName', value: commonName }
    ])

    cert.setSubject(attrs)
    cert.setIssuer(attrs)
    cert.setExtensions([
      { name: 'basicConstraints', cA: true }
    ])

    cert.sign(keys.privateKey, forge.md.sha256.create())

    var certPem = pki.certificateToPem(cert)
    var keyPem = pki.privateKeyToPem(keys.privateKey)

    fs.writeFileSync(rootCAcrt, certPem)
    fs.writeFileSync(rootCAkey, keyPem)
  },
  Domain(domain){
    let domaincrt = path.join(certsPath, domain.replace(/\*/g, "all") + '.crt')
    let domainkey = path.join(certsPath, domain.replace(/\*/g, "all") + '.key')

    if (fs.existsSync(domaincrt) && fs.existsSync(domainkey)) {
      console.log(domain + " 的证书已存在")
      return false
    } else {
      this.Root()
    }

    var caCertPem = fs.readFileSync(rootCAcrt)
    var caKeyPem = fs.readFileSync(rootCAkey)
    var caCert = pki.certificateFromPem(caCertPem)
    var caKey = pki.privateKeyFromPem(caKeyPem)

    var keys = pki.rsa.generateKeyPair(2048)
    var cert = pki.createCertificate()
    cert.publicKey = keys.publicKey

    cert.serialNumber = (new Date()).getTime() + ''
    cert.validity.notBefore = new Date()
    // cert.validity.notBefore.setFullYear(cert.validity.notBefore.getFullYear() - 1)
    cert.validity.notAfter = new Date()
    cert.validity.notAfter.setFullYear(cert.validity.notAfter.getFullYear() + 1)

    var attrs = defaultAttrs.concat([
      { name: 'commonName', value: domain }
    ])

    cert.setIssuer(caCert.subject.attributes)
    cert.setSubject(attrs)

    cert.setExtensions([
      { name: 'basicConstraints', cA: false },
      getExtensionSAN(domain)
    ])
    cert.sign(caKey, forge.md.sha256.create())

    var certPem = pki.certificateToPem(cert)
    var keyPem = pki.privateKeyToPem(keys.privateKey)

    fs.writeFileSync(domaincrt, certPem)
    fs.writeFileSync(domainkey, keyPem)

    return {
      key: keys.privateKey,
      cert: cert,
      path: certsPath
    }
  }
}