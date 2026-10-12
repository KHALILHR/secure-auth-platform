# Rapport de conception et de développement (LaTeX)

Rapport de SecureAuth dans le même plan que les autres rapports du module : introduction et contexte,
organisation du projet, architecture et conception (classes, cas d'utilisation, séquence d'inscription,
technologies), captures d'écran, conclusion et perspectives, glossaire.

PDF prêt à lire : [`../rapport-conception.pdf`](../rapport-conception.pdf).

## Compiler

Prérequis : une distribution TeX (MiKTeX ou TeX Live) avec `pdflatex` et `latexmk`.
Les diagrammes sont dessinés en TikZ (aucun outil externe).

```bash
cd docs/rapport
latexmk -pdf -outdir=build rapport-conception.tex
```

Sans `latexmk` : `pdflatex rapport-conception.tex`, deux fois.

## Contenu

| Fichier | Rôle |
|---|---|
| `rapport-conception.tex` | Texte du rapport |
| `uml-macros.tex` | Macros TikZ : acteurs, classes, lignes de vie, messages |
| `figures/` | Déploiement, classes, cas d'utilisation, séquence d'inscription |
| `img/captures/` | Captures des pages (rendues avec des données de démonstration) |
| `img/logos/` | Logos des technologies (SVG de Simple Icons + PDF convertis) |
| `img/tek_up_logo.jpg` | Logo de la page de garde |
