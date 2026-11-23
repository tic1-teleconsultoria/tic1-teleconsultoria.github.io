// Impede que o TIC1 seja aberto dentro de outro site (clickjacking).
if (window.top !== window.self) { try { window.top.location = window.self.location.href; } catch (e) { document.documentElement.innerHTML = ''; } }
window.__resources = {"https://unpkg.com/react@18.3.1/umd/react.production.min.js":"vendor/react.js?v=d949f1c368","https://unpkg.com/react-dom@18.3.1/umd/react-dom.production.min.js":"vendor/react-dom.js?v=35f4f974f4","https://unpkg.com/@babel/standalone@7.29.0/babel.min.js":"vendor/babel.js?v=2623a9e228"};
