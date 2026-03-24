package limiter

// UpdateUserRoute sets the outbound tag for a specific user UUID.
func (l *Limiter) UpdateUserRoute(uuid string, tag string) {
	l.userRouteLock.Lock()
	l.UserRoutes[uuid] = tag
	l.userRouteLock.Unlock()
}

// GetUserRoute returns the outbound tag for a specific user UUID.
func (l *Limiter) GetUserRoute(uuid string) string {
	l.userRouteLock.RLock()
	defer l.userRouteLock.RUnlock()
	if tag, ok := l.UserRoutes[uuid]; ok {
		return tag
	}
	return ""
}
