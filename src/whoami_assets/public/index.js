import whoami from 'ic:canisters/whoami';

whoami.greet(window.prompt("Enter your name:")).then(greeting => {
  window.alert(greeting);
});
