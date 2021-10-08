BIN_DIR := $(GOPATH)/bin
HUGO=$(BIN_DIR)/hugo

new: serve post

post: $(HUGO)
	$(eval POST := $(shell echo "\"posts/${TITLE}/index.md\""))
	hugo new $(POST)
	${EDITOR} content/$(POST) 

serve:
	tmux split-window -h -l 30%  'hugo serve -D --disableFastRender'


$(HUGO):
	go install --tags extended github.com/gohugoio/hugo@latest


.PHONY: new post serve
