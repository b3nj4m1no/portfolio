# portfolio

Personal website built with [Hugo](https://gohugo.io/) and the [Blowfish](https://github.com/nunocoracao/blowfish) theme.

## Setup

```bash
git clone --recurse-submodules https://github.com/b3nj4m1no/portfolio.git
cd portfolio
hugo server -D
```

The site will be available at `http://localhost:1313`.

## Structure

- `content/` — pages and blog posts
- `assets/css/custom.css` — custom styles
- `layouts/` — template overrides
- `config/_default/` — Hugo and theme configuration

## Deploy

Any static hosting works. Just run `hugo` and serve the `public/` folder.

## License

Content and code © Matthew Gasparetti.
