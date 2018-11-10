const why = require('./why')

window.addEventListener('load', function() {
  document.querySelector('form').addEventListener('submit', (ev) => {
    ev.preventDefault()
    result.innerText = why(input.value)
  })
})

