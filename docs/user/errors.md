# Errors and status codes

**In short:** every error the API returns has the same shape, RFC 9457 "problem details", so the frontend handles all of them in one place. The status code says what kind of problem it is; the body gives a short, safe explanation and never reveals how the server works inside.

Decision: [0026 API conventions](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0026-api-conventions.md). Code: `app/core/errors.py`.

## The shape

Media type `application/problem+json`:

```json
{
  "type": "about:blank",
  "title": "Forbidden",
  "status": 403,
  "detail": "Not allowed"
}
```

| Field | Meaning |
|---|---|
| `type` | always `about:blank` for now (no custom problem types yet) |
| `title` | the standard phrase for the status code |
| `status` | the HTTP status code, repeated in the body |
| `detail` | a short explanation for this case, when there is one |

**Invalid input (422)** adds an `errors` list, one entry per problem:

```json
{
  "type": "about:blank",
  "title": "Unprocessable Content",
  "status": 422,
  "errors": [
    { "location": "path.item_id", "message": "Input should be a valid integer, unable to parse string as an integer" }
  ]
}
```

`location` says where the problem is (`path`, `query`, or `body`, then the field name). The value that was sent is never copied back.

## Status codes

| Code | Title | Means | Example |
|---|---|---|---|
| 400 | Bad Request | the request could not be understood | malformed JSON |
| 401 | Unauthorized | not signed in (Phase 2) | no session cookie |
| 403 | Forbidden | signed in, but not allowed | an employee editing shifts |
| 404 | Not Found | no such path, or no such record **in your company** | another company's shift also answers 404 ([tenancy](../architecture/tenancy.md)) |
| 405 | Method Not Allowed | the path exists, the method does not | `POST /api/health` |
| 409 | Conflict | not allowed in the record's current state | changing a shift that has ended |
| 422 | Unprocessable Content | the input failed validation | text where a number was expected |
| 429 | Too Many Requests | a rate limit was hit (Phase 2) | too many sign-in attempts |
| 500 | Internal Server Error | something unexpected broke | always `"An unexpected error occurred."` |

## What is never in an error

- stack traces, exception messages, SQL, file paths, or setting values (a 500 always has the same generic text; the real error is in the server log);
- the input that was sent (echoing it back is how reflected cross-site scripting starts);
- whether a record exists in another company (those answer 404, exactly like a record that does not exist).
