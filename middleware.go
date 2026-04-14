package azuretls

func (s *Session) UseCallbackWithContext(callback func(ctx *Context)) {
	s.CallbacksWithContext = append(s.CallbacksWithContext, callback)
}

func (s *Session) UsePrehookWithContext(preHook func(ctx *Context) error) {
	s.PreHooksWithContext = append(s.PreHooksWithContext, preHook)
}
