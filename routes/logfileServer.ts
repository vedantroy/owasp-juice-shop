/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

export function serveLogFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (!file.includes('/')) {
      const sanitizedFile = path.basename(file)
      const resolvedPath = path.resolve('logs/', sanitizedFile)
      const logsDir = path.resolve('logs/')
      if (!resolvedPath.startsWith(logsDir + path.sep) && resolvedPath !== logsDir) {
        res.status(403)
        next(new Error('Invalid file path!'))
        return
      }
      res.sendFile(resolvedPath)
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }
}
